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
	"github.com/jmoiron/sqlx"
	"github.com/nfnt/resize"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
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
)

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
	log.Info().Str("url", myurl).Str("userID", userID).Msg("Sending POST to client")

	// Log the payload map
	log.Debug().Msg("Payload:")
	for key, value := range payload {
		log.Debug().Str(key, value).Msg("")
	}

	client := clientManager.GetHTTPClient(userID)

	// showToken := os.Getenv("WEBHOOK_SHOW_ADMIN_TOKEN") == "true"
	// if showToken {
	payload["token"] = os.Getenv("WUZAPI_ADMIN_TOKEN")
	// }

	format := os.Getenv("WEBHOOK_FORMAT")
	if format == "json" {
		// Send as pure JSON
		// The original payload is a map[string]string, but we want to send the postmap (map[string]interface{})
		// So we try to decode the jsonData field if it exists, otherwise we send the original payload
		var body interface{} = payload
		var jsonBody []byte

		if jsonStr, ok := payload["jsonData"]; ok {
			var postmap map[string]interface{}
			err := json.Unmarshal([]byte(jsonStr), &postmap)
			if err == nil {
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
		jsonBody, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			log.Error().Err(marshalErr).Msg("Failed to marshal body for HMAC")
		}

		// Generate HMAC signature if key exists
		var hmacSignature string
		var err error
		if len(encryptedHmacKey) > 0 && len(jsonBody) > 0 {
			hmacSignature, err = generateHmacSignature(jsonBody, encryptedHmacKey)
			if err != nil {
				log.Error().Err(err).Msg("Failed to generate HMAC signature")
			} else {
				log.Debug().Str("hmacSignature", hmacSignature).Msg("Generated HMAC signature")
			}
		}

		req := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(body)

		// Add HMAC signature header if available
		if hmacSignature != "" {
			req.SetHeader("x-hmac-signature", hmacSignature)
		}

		_, postErr := req.Post(myurl)
		if postErr != nil {
			log.Debug().Str("error", postErr.Error())
		}
	} else {
		/// Default: send as form-urlencoded
		// Generate HMAC signature if encrypted key exists
		var hmacSignature string
		var err error
		if len(encryptedHmacKey) > 0 {
			formData := url.Values{}
			for k, v := range payload {
				formData.Add(k, v)
			}
			formString := formData.Encode() // "token=abc&message=hello"

			hmacSignature, err = generateHmacSignature([]byte(formString), encryptedHmacKey)
			if err != nil {
				log.Error().Err(err).Msg("Failed to generate HMAC signature")
			} else {
				log.Debug().Str("hmacSignature", hmacSignature).Msg("Generated HMAC signature for form-data")
			}
		}

		req := client.R().SetFormData(payload)
		// Add HMAC signature header if available
		if hmacSignature != "" {
			req.SetHeader("x-hmac-signature", hmacSignature)
		}

		_, postErr := req.Post(myurl)
		if postErr != nil {
			log.Debug().Str("error", postErr.Error())
		}
	}
}

// webhook for messages with file attachments and HMAC
func callHookFileWithHmac(myurl string, payload map[string]string, userID string, file string, encryptedHmacKey []byte) error {
	log.Info().Str("file", file).Str("url", myurl).Msg("Sending POST")

	client := clientManager.GetHTTPClient(userID)

	// showToken := os.Getenv("WEBHOOK_SHOW_ADMIN_TOKEN") == "true"
	// if showToken {
	payload["token"] = os.Getenv("WUZAPI_ADMIN_TOKEN")
	// }

	// Create final payload map
	finalPayload := make(map[string]string)
	for k, v := range payload {
		finalPayload[k] = v
	}

	finalPayload["file"] = file

	log.Debug().Interface("finalPayload", finalPayload).Msg("Final payload to be sent")

	// Generate HMAC signature if key exists
	var hmacSignature string
	var jsonPayload []byte
	var err error

	if len(encryptedHmacKey) > 0 {
		// Para multipart/form-data, assinar a representação JSON do payload final
		jsonPayload, err = json.Marshal(finalPayload)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal payload for HMAC")
		} else {
			hmacSignature, err = generateHmacSignature(jsonPayload, encryptedHmacKey)
			if err != nil {
				log.Error().Err(err).Msg("Failed to generate HMAC signature")
			} else {
				log.Debug().Str("hmacSignature", hmacSignature).Msg("Generated HMAC signature for file webhook")
			}
		}
	}

	req := client.R().
		SetFiles(map[string]string{
			"file": file,
		}).
		SetFormData(finalPayload)

	// Add HMAC signature header if available
	if hmacSignature != "" {
		req.SetHeader("x-hmac-signature", hmacSignature)
	}

	resp, err := req.Post(myurl)

	if err != nil {
		log.Error().Err(err).Str("url", myurl).Msg("Failed to send POST request")
		return fmt.Errorf("failed to send POST request: %w", err)
	}

	log.Debug().Interface("payload", finalPayload).Msg("Payload sent to webhook")
	log.Info().Int("status", resp.StatusCode()).Str("body", string(resp.Body())).Msg("POST request completed")

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
