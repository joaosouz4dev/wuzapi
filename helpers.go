package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-resty/resty/v2"
	"github.com/jmoiron/sqlx"
	"github.com/nfnt/resize"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/vincent-petithory/dataurl"
	_ "golang.org/x/image/webp"
	"golang.org/x/sync/singleflight"
)

const (
	openGraphFetchTimeout    = 5 * time.Second
	openGraphPageMaxBytes    = 2 * 1024 * 1024   // 2MB
	openGraphImageMaxBytes   = 10 * 1024 * 1024  // 10MB
	openGraphAudioMaxBytes   = 50 * 1024 * 1024  // 50MB
	openGraphDocMaxBytes     = 100 * 1024 * 1024 // 100MB
	openGraphThumbnailWidth  = 100
	openGraphThumbnailHeight = 100
	openGraphJpegQuality     = 80
	openGraphMaxImageDim     = 4000 // Max width or height for Open Graph images
	openGraphUserFetchLimit  = 20   // Limit concurrent Open Graph fetches per user

	// WebP RIFF container constants
	riffHeaderSize  = 12 // "RIFF" + size (4) + "WEBP"
	chunkHeaderSize = 8  // tag (4) + size (4)
	riffSizeOffset  = 4  // Offset to RIFF size field

	// VP8X extended header chunk layout (10-byte payload)
	vp8xChunkSize    = chunkHeaderSize + 10
	vp8xPayloadSize  = 10
	vp8xFlagsOffset  = chunkHeaderSize     // Byte 0 of payload: feature flags
	vp8xWidthOffset  = chunkHeaderSize + 4 // Bytes 4-6: canvas width - 1 (24-bit LE)
	vp8xHeightOffset = chunkHeaderSize + 7 // Bytes 7-9: canvas height - 1 (24-bit LE)

	// VP8X feature flags
	vp8xFlagEXIF byte = 0x08
)

type WebhookFileErrorPayload struct {
	URL              string                 `json:"url"`
	Payload          map[string]interface{} `json:"payload"`
	UserID           string                 `json:"userID"`
	EncryptedHmacKey string                 `json:"encryptedHmacKey"`
	FilePath         string                 `json:"filePath"`
	AttemptTime      time.Time              `json:"attemptTime"`
	ErrorMessage     string                 `json:"errorMessage"`
}

type WebhookErrorPayload struct {
	URL              string                 `json:"url"`
	Payload          map[string]interface{} `json:"payload"`
	UserID           string                 `json:"userID"`
	EncryptedHmacKey string                 `json:"encryptedHmacKey"`
	AttemptTime      time.Time              `json:"attemptTime"`
	ErrorMessage     string                 `json:"errorMessage"`
}
type openGraphResult struct {
	Title       string
	Description string
	ImageData   []byte
}

type UserSemaphoreManager struct {
	pools sync.Map
}

func NewUserSemaphoreManager() *UserSemaphoreManager {
	return &UserSemaphoreManager{}
}

func (usm *UserSemaphoreManager) ForUser(userID string) chan struct{} {
	// LoadOrStore provides an atomic way to get or create a semaphore.
	pool, _ := usm.pools.LoadOrStore(userID, make(chan struct{}, openGraphUserFetchLimit))
	return pool.(chan struct{})
}

var (
	urlRegex = regexp.MustCompile(`https?://[^\s"']*[^\"'\s\.,!?()[\]{}]`)

	userSemaphoreManager = NewUserSemaphoreManager()

	openGraphGroup singleflight.Group

	openGraphCache = cache.New(5*time.Minute, 10*time.Minute) // Cache Open Graph data for 5 minutes, cleanup every 10 minutes

)

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func isHTTPURL(input string) bool {
	parsed, err := url.ParseRequestURI(input)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return parsed.Host != ""
}
func fetchURLBytes(ctx context.Context, resourceURL string, limit int64) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", resourceURL, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := globalHTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, limit+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) > limit {
		return nil, "", fmt.Errorf("response exceeds allowed size (%d bytes)", limit)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}

	return data, contentType, nil
}

func getOpenGraphData(ctx context.Context, urlStr string, userID string) (title, description string, imageData []byte) {
	// Check cache first
	if cachedData, found := openGraphCache.Get(urlStr); found {
		if data, ok := cachedData.(openGraphResult); ok {
			log.Debug().Str("url", urlStr).Msg("Open Graph data fetched from cache")
			return data.Title, data.Description, data.ImageData
		}
	}

	v, err, _ := openGraphGroup.Do(urlStr, func() (res any, err error) {
		ctx, cancel := context.WithTimeout(ctx, openGraphFetchTimeout)
		defer cancel()

		// Acquire a token from the semaphore pool
		userPool := userSemaphoreManager.ForUser(userID)
		select {
		case userPool <- struct{}{}:
			defer func() { <-userPool }()
		case <-ctx.Done():
			log.Warn().Str("url", urlStr).Msg("Open Graph data fetch timed out while waiting for a worker")
			return nil, ctx.Err()
		}

		// Recover from panics and convert to error
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				log.Error().
					Interface("panic_info", r).
					Str("url", urlStr).
					Bytes("stack", stack).
					Msg("Panic recovered while fetching Open Graph data")
				err = fmt.Errorf("panic: %v", r)
			}
		}()

		// Fetch Open Graph data
		title, description, imageData := fetchOpenGraphData(ctx, urlStr)

		// Store in cache
		openGraphCache.Set(urlStr, openGraphResult{title, description, imageData}, cache.DefaultExpiration)

		return openGraphResult{title, description, imageData}, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", urlStr).Msg("Error fetching Open Graph data via singleflight")
		return "", "", nil
	}

	if v == nil {
		return "", "", nil
	}

	data := v.(openGraphResult)
	return data.Title, data.Description, data.ImageData
}

// Update entry in User map
func updateUserInfo(values interface{}, field string, value string) interface{} {
	log.Debug().Str("field", field).Str("value", value).Msg("User info updated")
	values.(Values).m[field] = value
	return values
}

// webhook for regular messages with HMAC
func callHookWithHmac(myurl string, payload map[string]string, userID string, encryptedHmacKey []byte) {
	log.Info().Str("url", myurl).Str("userID", userID).Msg("Sending POST to client with retry logic")

	client := clientManager.GetHTTPClient(userID)

	// Retry settings
	maxRetries := 1
	if *webhookRetryEnabled {
		maxRetries = *webhookRetryCount
	}

	var lastError error

	var body interface{} = payload

	// Starts the retry loop.
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoffFactor := 1 << uint(attempt-1)

			// Calculate the final delay.
			delayDuration := time.Duration(*webhookRetryDelaySeconds) * time.Second * time.Duration(backoffFactor)

			log.Warn().
				Int("attempt", attempt+1).
				Str("url", myurl).
				Dur("delay", delayDuration).
				Msg("Retrying webhook request with exponential backoff...")

			time.Sleep(delayDuration)
		}

		var req *resty.Request
		var hmacSignature string
		var marshalErr error

		format := os.Getenv("WEBHOOK_FORMAT")

		if format == "json" {
			var jsonBody []byte

			if jsonStr, ok := payload["jsonData"]; ok {
				var postmap map[string]interface{}

				if err := json.Unmarshal([]byte(jsonStr), &postmap); err == nil {
					if instanceName, ok := payload["instanceName"]; ok {
						postmap["instanceName"] = instanceName
					}
					postmap["userID"] = userID

					if token, ok := payload["token"]; ok && token != "" {
						postmap["token"] = token
					}

					body = postmap
				}
			}

			// Marshal body to JSON for HMAC signature
			jsonBody, marshalErr = json.Marshal(body)
			if marshalErr != nil {
				log.Error().Err(marshalErr).Msg("Failed to marshal body for HMAC")
			}

			// Generate HMAC signature if key exists
			if len(encryptedHmacKey) > 0 && len(jsonBody) > 0 {
				var err error
				hmacSignature, err = generateHmacSignature(jsonBody, encryptedHmacKey)
				if err != nil {
					log.Error().Err(err).Msg("Failed to generate HMAC signature")
				}
			}

			req = client.R().SetHeader("Content-Type", "application/json").SetBody(body)

		} else {

			if len(encryptedHmacKey) > 0 {
				formData := url.Values{}
				for k, v := range payload {
					formData.Add(k, v)
				}
				formString := formData.Encode()
				var err error
				hmacSignature, err = generateHmacSignature([]byte(formString), encryptedHmacKey)
				if err != nil {
					log.Error().Err(err).Msg("Failed to generate HMAC signature")
				}
			}
			req = client.R().SetFormData(payload)
			body = payload
		}

		if hmacSignature != "" {
			req.SetHeader("x-hmac-signature", hmacSignature)
		}

		resp, postErr := req.Post(myurl)

		lastError = postErr

		if postErr != nil {
			log.Error().Err(postErr).Int("attempt", attempt+1).Str("url", myurl).Msg("Webhook failed due to network/IO error")
			continue
		}

		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			lastError = fmt.Errorf("unexpected status code: %d. Body: %s", resp.StatusCode(), string(resp.Body()))
			log.Error().
				Int("status", resp.StatusCode()).
				Int("attempt", attempt+1).
				Str("url", myurl).
				Msg("Webhook failed due to non-2xx status code")

			if !*webhookRetryEnabled {
				break
			}
			continue
		}

		log.Info().Int("status", resp.StatusCode()).Str("url", myurl).Msg("Webhook call successful")
		return
	}

	if lastError != nil {
		log.Error().Str("url", myurl).Msg("Webhook permanently failed after all retries. Sending to error queue...")

		errorPayloadMap := make(map[string]interface{})
		if p, ok := body.(map[string]string); ok {

			for k, v := range p {
				errorPayloadMap[k] = v
			}
		} else if p, ok := body.(map[string]interface{}); ok {

			errorPayloadMap = p
		}

		errorPayload := WebhookErrorPayload{
			URL:              myurl,
			Payload:          errorPayloadMap,
			UserID:           userID,
			EncryptedHmacKey: hex.EncodeToString(encryptedHmacKey),
			AttemptTime:      time.Now(),
			ErrorMessage:     lastError.Error(),
		}

		PublishDataErrorToQueue(errorPayload)
	}
}

// webhook for messages with file attachments and HMAC
func callHookFileWithHmac(myurl string, payload map[string]string, userID string, file string, encryptedHmacKey []byte) error {
	log.Info().Str("file", file).Str("url", myurl).Msg("Sending POST with retry logic")

	client := clientManager.GetHTTPClient(userID)

	maxRetries := 1
	if *webhookRetryEnabled {
		maxRetries = *webhookRetryCount
	}

	var lastError error

	finalPayload := make(map[string]string)
	for k, v := range payload {
		finalPayload[k] = v
	}
	finalPayload["file"] = file

	// 2. Loop Retry
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoffFactor := 1 << uint(attempt-1)

			delayDuration := time.Duration(*webhookRetryDelaySeconds) * time.Second * time.Duration(backoffFactor)

			log.Warn().
				Int("attempt", attempt+1).
				Str("url", myurl).
				Dur("delay", delayDuration).
				Msg("Retrying file webhook request with exponential backoff...")

			time.Sleep(delayDuration)
		}

		var hmacSignature string
		var jsonPayload []byte

		if len(encryptedHmacKey) > 0 {
			var err error
			jsonPayload, err = json.Marshal(finalPayload)
			if err != nil {
				log.Error().Err(err).Msg("Failed to marshal payload for HMAC")
			} else {
				hmacSignature, err = generateHmacSignature(jsonPayload, encryptedHmacKey)
				if err != nil {
					log.Error().Err(err).Msg("Failed to generate HMAC signature")
				}
			}
		}

		req := client.R().
			SetFiles(map[string]string{
				"file": file,
			}).
			SetFormData(finalPayload)

		if hmacSignature != "" {
			req.SetHeader("x-hmac-signature", hmacSignature)
		}

		resp, postErr := req.Post(myurl)

		lastError = postErr

		if postErr != nil {
			log.Error().Err(postErr).Int("attempt", attempt+1).Str("url", myurl).Msg("File webhook failed due to network/IO error")
			continue
		}

		if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
			lastError = fmt.Errorf("unexpected status code: %d. Body: %s", resp.StatusCode(), string(resp.Body()))
			log.Error().
				Int("status", resp.StatusCode()).
				Int("attempt", attempt+1).
				Str("url", myurl).
				Msg("File webhook failed due to non-2xx status code")

			if !*webhookRetryEnabled {
				break
			}
			continue
		}

		log.Info().Int("status", resp.StatusCode()).Str("url", myurl).Msg("File webhook call successful")
		return nil
	}

	if lastError != nil {
		log.Error().Str("url", myurl).Msg("File webhook permanently failed after all retries. Sending to error queue...")

		errorPayloadMap := make(map[string]interface{})
		for k, v := range finalPayload {
			errorPayloadMap[k] = v
		}

		errorPayload := WebhookFileErrorPayload{
			URL:              myurl,
			Payload:          errorPayloadMap,
			UserID:           userID,
			EncryptedHmacKey: hex.EncodeToString(encryptedHmacKey),
			FilePath:         file,
			AttemptTime:      time.Now(),
			ErrorMessage:     lastError.Error(),
		}

		PublishFileErrorToQueue(errorPayload)

		return fmt.Errorf("webhook failed permanently: %w", lastError)
	}

	return nil
}

func (s *server) respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(payload); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(statusCode)
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Error().Err(err).Msg("Failed to write response body")
	}
}

// ProcessOutgoingMedia handles media processing for outgoing messages with S3 support
func ProcessOutgoingMedia(userID string, contactJID string, messageID string, data []byte, mimeType string, fileName string, db *sqlx.DB) (map[string]interface{}, error) {
	// Check if S3 is enabled for this user
	var s3Config struct {
		Enabled       bool   `db:"s3_enabled"`
		MediaDelivery string `db:"media_delivery"`
	}
	err := db.Get(&s3Config, "SELECT s3_enabled, media_delivery FROM users WHERE id = $1", userID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get S3 config")
		s3Config.Enabled = false
		s3Config.MediaDelivery = "base64"
	}

	// Process S3 upload if enabled
	if s3Config.Enabled && (s3Config.MediaDelivery == "s3" || s3Config.MediaDelivery == "both") {
		// Process S3 upload (outgoing messages are always in outbox)
		s3Data, err := GetS3Manager().ProcessMediaForS3(
			context.Background(),
			userID,
			contactJID,
			messageID,
			data,
			mimeType,
			fileName,
			false, // isIncoming = false for sent messages
		)
		if err != nil {
			log.Error().Err(err).Msg("Failed to upload media to S3")
			// Continue even if S3 upload fails
		} else {
			return s3Data, nil
		}
	}

	return nil, nil
}

// generateHmacSignature generates HMAC-SHA256 signature for webhook payload
func generateHmacSignature(payload []byte, encryptedHmacKey []byte) (string, error) {
	if len(encryptedHmacKey) == 0 {
		return "", nil
	}

	// Decrypt HMAC key
	hmacKey, err := decryptHMACKey(encryptedHmacKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt HMAC key: %w", err)
	}

	// Generate HMAC
	h := hmac.New(sha256.New, []byte(hmacKey))
	h.Write(payload)

	return hex.EncodeToString(h.Sum(nil)), nil
}

func encryptHMACKey(plainText string) ([]byte, error) {
	if *globalEncryptionKey == "" {
		return nil, fmt.Errorf("encryption key not configured")
	}

	block, err := aes.NewCipher([]byte(*globalEncryptionKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return ciphertext, nil
}

// decryptHMACKey decrypts HMAC key using AES-GCM
func decryptHMACKey(encryptedData []byte) (string, error) {
	if *globalEncryptionKey == "" {
		return "", fmt.Errorf("encryption key not configured")
	}

	block, err := aes.NewCipher([]byte(*globalEncryptionKey))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

func extractFirstURL(text string) string {
	match := urlRegex.FindString(text)
	if match == "" {
		return ""
	}

	return match
}
func fetchOpenGraphData(ctx context.Context, urlStr string) (string, string, []byte) {
	pageData, _, err := fetchURLBytes(ctx, urlStr, openGraphPageMaxBytes)
	if err != nil {
		log.Warn().Err(err).Str("url", urlStr).Msg("Failed to fetch URL for Open Graph data")
		return "", "", nil
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(pageData))
	if err != nil {
		log.Warn().Err(err).Str("url", urlStr).Msg("Failed to parse HTML for Open Graph data")
		return "", "", nil
	}

	title := doc.Find(`meta[property="og:title"]`).AttrOr("content", "")
	if title == "" {
		title = strings.TrimSpace(doc.Find("title").Text())
	}

	description := doc.Find(`meta[property="og:description"]`).AttrOr("content", "")
	if description == "" {
		description = doc.Find(`meta[name="description"]`).AttrOr("content", "")
	}

	var imageURLStr string
	selectors := []struct {
		selector string
		attr     string
	}{
		{`meta[property="og:image"]`, "content"},
		{`meta[property="twitter:image"]`, "content"},
		{`link[rel="apple-touch-icon"]`, "href"},
		{`link[rel="icon"]`, "href"},
	}

	for _, s := range selectors {
		imageURLStr, _ = doc.Find(s.selector).Attr(s.attr)
		if imageURLStr != "" {
			break
		}
	}

	pageURL, err := url.Parse(urlStr)
	if err != nil {
		log.Warn().Err(err).Str("url", urlStr).Msg("Failed to parse page URL for resolving image URL")
		return title, description, nil
	}

	imageData := fetchOpenGraphImage(ctx, pageURL, imageURLStr)
	return title, description, imageData
}

func fetchOpenGraphImage(ctx context.Context, pageURL *url.URL, imageURLStr string) []byte {
	imageURL, err := url.Parse(imageURLStr)
	if err != nil {
		log.Warn().Err(err).Str("imageURL", imageURLStr).Msg("Failed to parse Open Graph image URL")
		return nil
	}

	resolvedImageURL := pageURL.ResolveReference(imageURL).String()
	imgBytes, _, err := fetchURLBytes(ctx, resolvedImageURL, openGraphImageMaxBytes)
	if err != nil {
		log.Warn().Err(err).Str("imageURL", resolvedImageURL).Msg("Failed to fetch Open Graph image")
		return nil
	}

	imgConfig, _, err := image.DecodeConfig(bytes.NewReader(imgBytes))
	if err != nil {
		log.Warn().Err(err).Str("imageURL", resolvedImageURL).Msg("Failed to decode Open Graph image config")
		return nil
	}

	if imgConfig.Width > openGraphMaxImageDim || imgConfig.Height > openGraphMaxImageDim {
		log.Warn().
			Int("width", imgConfig.Width).
			Int("height", imgConfig.Height).
			Str("imageURL", resolvedImageURL).
			Msg("Open Graph image dimensions too large")
		return nil
	}

	img, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		log.Warn().Err(err).Str("imageURL", resolvedImageURL).Msg("Failed to decode Open Graph image")
		return nil
	}

	thumbnail := resize.Thumbnail(openGraphThumbnailWidth, openGraphThumbnailHeight, img, resize.Lanczos3)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, thumbnail, &jpeg.Options{Quality: openGraphJpegQuality}); err != nil {
		log.Warn().Err(err).Msg("Failed to encode thumbnail to JPEG")
		return nil
	}

	return buf.Bytes()
}

func GenerateAudioWaveformFromOggOpus(opusData []byte) ([]byte, error) {
	// Cria arquivo temporário para o ffmpeg consumir
	tmpFile, err := os.CreateTemp("", "audio-*.ogg")
	if err != nil {
		return nil, fmt.Errorf("falha ao criar temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := tmpFile.Write(opusData); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("falha ao escrever temp file: %w", err)
	}
	_ = tmpFile.Close()

	// Usa ffmpeg para decodificar para PCM s16le, mono, 16kHz, na saída padrão
	cmd := exec.Command(
		"ffmpeg",
		"-v", "error",
		"-i", tmpFile.Name(),
		"-ac", "1",
		"-ar", "16000",
		"-f", "s16le",
		"pipe:1",
	)

	pcmBytes, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ffmpeg falhou ao decodificar áudio: %w", err)
	}

	if len(pcmBytes) < 2 {
		return nil, nil
	}

	// Converte bytes em amostras int16 (little-endian)
	numSamples := len(pcmBytes) / 2
	intSamples := make([]int16, numSamples)
	for i := 0; i < numSamples; i++ {
		intSamples[i] = int16(binary.LittleEndian.Uint16(pcmBytes[i*2 : i*2+2]))
	}

	// Converte para amplitudes absolutas normalizadas (0..1)
	floatAbs := make([]float64, numSamples)
	const maxInt16 = 32768.0
	for i := 0; i < numSamples; i++ {
		v := float64(intSamples[i])
		if v < 0 {
			v = -v
		}
		floatAbs[i] = v / maxInt16
	}

	// Agrega em 64 amostras por média dos valores absolutos
	const samples = 64
	if numSamples == 0 {
		return make([]byte, samples), nil
	}
	blockSize := numSamples / samples
	if blockSize < 1 {
		blockSize = 1
	}
	filtered := make([]float64, samples)
	for i := 0; i < samples; i++ {
		start := i * blockSize
		if start >= numSamples {
			break
		}
		end := start + blockSize
		if end > numSamples {
			end = numSamples
		}
		sum := 0.0
		for j := start; j < end; j++ {
			sum += floatAbs[j]
		}
		filtered[i] = sum / float64(end-start)
	}

	// Normaliza para que o maior seja 1 e escala para 0..100
	maxVal := 0.0
	for _, v := range filtered {
		if v > maxVal {
			maxVal = v
		}
	}
	wave := make([]byte, samples)
	if maxVal <= 0 {
		// tudo zero
		return wave, nil
	}
	for i, v := range filtered {
		scaled := int(math.Floor(100.0 * (v / maxVal)))
		if scaled < 0 {
			scaled = 0
		} else if scaled > 100 {
			scaled = 100
		}
		wave[i] = byte(scaled)
	}
	return wave, nil
}

// GetAudioDuration obtém a duração de um áudio OGG/Opus em segundos usando ffmpeg
// Similar ao getAudioDuration do Node.js que usa music-metadata
func GetAudioDuration(audioData []byte) (uint32, error) {
	// Cria arquivo temporário para o ffmpeg analisar
	tmpFile, err := os.CreateTemp("", "audio-duration-*.ogg")
	if err != nil {
		return 0, fmt.Errorf("falha ao criar temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := tmpFile.Write(audioData); err != nil {
		_ = tmpFile.Close()
		return 0, fmt.Errorf("falha ao escrever temp file: %w", err)
	}
	_ = tmpFile.Close()

	// Usa ffprobe para obter duração em segundos
	cmd := exec.Command(
		"ffprobe",
		"-v", "quiet",
		"-show_entries", "format=duration",
		"-of", "csv=p=0",
		tmpFile.Name(),
	)

	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("ffprobe falhou ao obter duração: %w", err)
	}

	durationStr := strings.TrimSpace(string(output))
	if durationStr == "" {
		return 0, fmt.Errorf("duração não encontrada")
	}

	// Converte string para float64 e depois para uint32 (segundos)
	duration, err := strconv.ParseFloat(durationStr, 64)
	if err != nil {
		return 0, fmt.Errorf("falha ao converter duração: %w", err)
	}

	return uint32(math.Round(duration)), nil
}

// ConvertAudioToOggOpus converte qualquer formato de áudio para OGG/Opus usando ffmpeg
// Similar ao que seria feito no Node.js para garantir compatibilidade com WhatsApp
func ConvertAudioToOggOpus(audioData []byte) ([]byte, error) {
	// Cria arquivo temporário de entrada
	inputFile, err := os.CreateTemp("", "input-audio-*")
	if err != nil {
		return nil, fmt.Errorf("falha ao criar temp file de entrada: %w", err)
	}
	defer func() {
		_ = os.Remove(inputFile.Name())
	}()

	// Escreve dados de entrada
	if _, err := inputFile.Write(audioData); err != nil {
		_ = inputFile.Close()
		return nil, fmt.Errorf("falha ao escrever temp file de entrada: %w", err)
	}
	_ = inputFile.Close()

	// Cria arquivo temporário de saída
	outputFile, err := os.CreateTemp("", "output-audio-*.ogg")
	if err != nil {
		return nil, fmt.Errorf("falha ao criar temp file de saída: %w", err)
	}
	outputPath := outputFile.Name()
	_ = outputFile.Close()
	defer func() {
		_ = os.Remove(outputPath)
	}()

	// Executa ffmpeg para converter para OGG/Opus
	// Parâmetros otimizados para WhatsApp:
	// - codec opus para áudio
	// - bitrate 64k (boa qualidade/tamanho)
	// - sample rate 48kHz (padrão Opus)
	// - mono (WhatsApp prefere mono para PTT)
	cmd := exec.Command(
		"ffmpeg",
		"-i", inputFile.Name(), // arquivo de entrada
		"-c:a", "libopus", // codec Opus
		"-b:a", "64k", // bitrate 64kbps
		"-ar", "48000", // sample rate 48kHz
		"-ac", "1", // mono
		"-application", "voip", // otimizado para voz
		"-frame_duration", "20", // frame duration 20ms
		"-y", // sobrescrever arquivo de saída
		outputPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("falha na conversão ffmpeg: %w, output: %s", err, string(output))
	}

	// Lê o arquivo convertido
	convertedData, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("falha ao ler arquivo convertido: %w", err)
	}

	if len(convertedData) == 0 {
		return nil, fmt.Errorf("arquivo convertido está vazio")
	}

	return convertedData, nil
}

// AssertColor converte uma cor (string hex ou número) para uint32 ARGB
// Similar ao assertColor do Node.js para backgroundColor em mensagens de áudio
func AssertColor(color interface{}) (uint32, error) {
	switch v := color.(type) {
	case int:
		return assertColorFromInt(v), nil
	case int32:
		return assertColorFromInt(int(v)), nil
	case int64:
		return assertColorFromInt(int(v)), nil
	case uint32:
		return v, nil
	case string:
		return assertColorFromString(v)
	default:
		return 0, fmt.Errorf("tipo de cor não suportado: %T", color)
	}
}

func assertColorFromInt(color int) uint32 {
	if color > 0 {
		return uint32(color)
	}
	// Para números negativos, converte seguindo a lógica do Node.js
	return uint32(0xffffffff + color + 1)
}

func assertColorFromString(color string) (uint32, error) {
	hex := strings.TrimSpace(color)
	hex = strings.TrimPrefix(hex, "#")

	// Se tem 6 caracteres ou menos, adiciona FF (alpha) no início
	if len(hex) <= 6 {
		hex = "FF" + strings.Repeat("0", 6-len(hex)) + hex
	}

	// Converte hex para uint32
	result, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("falha ao converter hex para cor: %w", err)
	}

	return uint32(result), nil
}

func runFFmpegConversion(input []byte, inputExt string, ffmpegArgs func(inPath, outPath string) []string, errMsg string) ([]byte, error) {
	inFile, err := os.CreateTemp("", "sticker-input-*"+inputExt)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inFile.Name())
	defer inFile.Close()

	if _, err := inFile.Write(input); err != nil {
		return nil, err
	}

	outFile, err := os.CreateTemp("", "sticker-output-*.webp")
	if err != nil {
		return nil, err
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	args := ffmpegArgs(inFile.Name(), outPath)
	cmd := exec.Command("ffmpeg", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("stderr", stderr.String()).Msg(errMsg)
		return nil, err
	}

	return os.ReadFile(outPath)
}

func convertVideoStickerToWebP(input []byte) ([]byte, error) {
	return runFFmpegConversion(input, ".mp4", func(inPath, outPath string) []string {
		return []string{
			"-y",
			"-t", "10",
			"-i", inPath,
			"-vf", "fps=15,scale=512:512",
			"-loop", "0",
			"-an",
			"-vsync", "0",
			"-fs", "1000000",
			"-c:v", "libwebp",
			"-qscale:v", "10",
			outPath,
		}
	}, "ffmpeg failed converting video sticker")
}

func convertImageToWebP(input []byte) ([]byte, error) {
	return runFFmpegConversion(input, ".img", func(inPath, outPath string) []string {
		return []string{
			"-y",
			"-i", inPath,
			"-vf", "scale=512:512",
			"-c:v", "libwebp",
			"-lossless", "1",
			outPath,
		}
	}, "ffmpeg failed converting image sticker")
}

func processStickerData(stickerData string, mimeOverride string, packID, packName, packPublisher string, emojis []string) ([]byte, string, error) {
	if !strings.HasPrefix(stickerData, "data") {
		return nil, "", fmt.Errorf("data should start with \"data:mime/type;base64,\"")
	}

	dataURL, err := dataurl.DecodeString(stickerData)
	if err != nil {
		return nil, "", fmt.Errorf("could not decode base64 encoded data from payload")
	}

	filedata, mimeType, err := convertToWebPSticker(dataURL.Data, mimeOverride)
	if err != nil {
		return nil, "", err
	}

	if mimeType == "image/webp" {
		filedata = embedStickerEXIF(filedata, packID, packName, packPublisher, emojis)
	}

	return filedata, mimeType, nil
}

func convertToWebPSticker(data []byte, mimeOverride string) ([]byte, string, error) {
	mimeType := http.DetectContentType(data)
	if mimeOverride != "" {
		mimeType = mimeOverride
	}

	switch {
	case strings.HasPrefix(mimeType, "video/"), mimeType == "image/gif":
		converted, err := convertVideoStickerToWebP(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to convert video/gif sticker to webp: %w", err)
		}
		return converted, "image/webp", nil

	case mimeType == "image/jpeg", mimeType == "image/png", mimeType == "image/jpg":
		converted, err := convertImageToWebP(data)
		if err != nil {
			return nil, "", fmt.Errorf("failed to convert image sticker to webp: %w", err)
		}
		return converted, "image/webp", nil

	default:
		return data, mimeType, nil
	}
}

func embedStickerEXIF(inputWebP []byte, packID, packName, packPublisher string, emojis []string) []byte {
	meta := buildStickerMetadata(packID, packName, packPublisher, emojis)
	if meta == nil {
		return inputWebP
	}

	exifData := buildWhatsAppEXIF(meta)
	out, err := injectWebPEXIF(inputWebP, exifData)
	if err != nil {
		log.Warn().Err(err).Msg("failed to inject EXIF chunk; sending sticker without metadata")
		return inputWebP
	}
	return out
}

func buildStickerMetadata(packID, packName, packPublisher string, emojis []string) map[string]interface{} {
	if packID == "" && packName == "" && packPublisher == "" && len(emojis) == 0 {
		return nil
	}

	meta := make(map[string]interface{})
	if packID != "" {
		meta["sticker-pack-id"] = packID
	}
	if packName != "" {
		meta["sticker-pack-name"] = packName
	}
	if packPublisher != "" {
		meta["sticker-pack-publisher"] = packPublisher
	}
	if len(emojis) > 0 {
		meta["emojis"] = emojis
	}
	return meta
}

func buildWhatsAppEXIF(meta map[string]interface{}) []byte {
	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		return nil
	}

	// WhatsApp sticker EXIF header structure
	header := []byte{
		0x49, 0x49, 0x2A, 0x00, // TIFF little-endian marker
		0x08, 0x00, 0x00, 0x00, // IFD offset
		0x01, 0x00, // Number of directory entries
		0x41, 0x57, // Tag ID (WhatsApp custom)
		0x07, 0x00, // Data type (undefined)
	}
	footer := []byte{0x16, 0x00, 0x00, 0x00} // Next IFD offset

	var buf bytes.Buffer
	buf.Write(header)
	binary.Write(&buf, binary.LittleEndian, uint32(len(jsonBytes)))
	buf.Write(footer)
	buf.Write(jsonBytes)

	return buf.Bytes()
}

func injectWebPEXIF(in []byte, exif []byte) ([]byte, error) {
	if !isValidWebP(in) {
		return nil, fmt.Errorf("not a RIFF WEBP file")
	}

	cfg, _, err := image.DecodeConfig(bytes.NewReader(in))
	if err != nil {
		return nil, fmt.Errorf("failed to decode image config: %w", err)
	}

	chunks, vp8xIndex, err := parseWebPChunks(in)
	if err != nil {
		return nil, err
	}

	chunks = ensureVP8XWithEXIF(chunks, vp8xIndex, cfg.Width, cfg.Height)

	return assembleWebP(chunks, exif), nil
}

func isValidWebP(data []byte) bool {
	return len(data) >= riffHeaderSize &&
		string(data[0:4]) == "RIFF" &&
		string(data[8:12]) == "WEBP"
}

func parseWebPChunks(in []byte) (chunks [][]byte, vp8xIndex int, err error) {
	vp8xIndex = -1
	pos := riffHeaderSize

	for pos+chunkHeaderSize <= len(in) {
		tag := string(in[pos : pos+4])
		size := int(binary.LittleEndian.Uint32(in[pos+4 : pos+8]))
		dataEnd := pos + chunkHeaderSize + size

		if dataEnd > len(in) {
			return nil, -1, fmt.Errorf("truncated webp chunk: %s", tag)
		}

		pad := size & 1
		if tag == "VP8X" && size >= vp8xPayloadSize {
			vp8xIndex = len(chunks)
		}
		if tag != "EXIF" {
			chunk := make([]byte, chunkHeaderSize+size+pad)
			copy(chunk, in[pos:dataEnd])
			if pad == 1 {
				chunk[chunkHeaderSize+size] = 0
			}
			chunks = append(chunks, chunk)
		}
		pos = dataEnd + pad
	}
	return chunks, vp8xIndex, nil
}

func ensureVP8XWithEXIF(chunks [][]byte, vp8xIndex, width, height int) [][]byte {
	if vp8xIndex >= 0 {
		chunks[vp8xIndex][vp8xFlagsOffset] |= vp8xFlagEXIF
		return chunks
	}
	return append([][]byte{createVP8XChunk(width, height)}, chunks...)
}

func createVP8XChunk(width, height int) []byte {
	chunk := make([]byte, vp8xChunkSize)
	copy(chunk[0:4], "VP8X")
	binary.LittleEndian.PutUint32(chunk[4:8], vp8xPayloadSize)
	chunk[vp8xFlagsOffset] = vp8xFlagEXIF
	putUint24LE(chunk[vp8xWidthOffset:], width-1)
	putUint24LE(chunk[vp8xHeightOffset:], height-1)
	return chunk
}

func putUint24LE(b []byte, v int) {
	b[0] = uint8(v)
	b[1] = uint8(v >> 8)
	b[2] = uint8(v >> 16)
}

func assembleWebP(chunks [][]byte, exif []byte) []byte {
	var out bytes.Buffer
	out.WriteString("RIFF")
	out.Write([]byte{0, 0, 0, 0})
	out.WriteString("WEBP")

	for _, c := range chunks {
		out.Write(c)
	}

	writeChunk(&out, "EXIF", exif)

	b := out.Bytes()
	binary.LittleEndian.PutUint32(b[riffSizeOffset:], uint32(len(b)-8))
	return b
}

func writeChunk(buf *bytes.Buffer, tag string, data []byte) {
	buf.WriteString(tag)
	sz := make([]byte, 4)
	binary.LittleEndian.PutUint32(sz, uint32(len(data)))
	buf.Write(sz)
	buf.Write(data)
	if len(data)%2 == 1 {
		buf.WriteByte(0)
	}
}
