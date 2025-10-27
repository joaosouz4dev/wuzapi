package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
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

func fetchURLBytes(resourceURL string) ([]byte, string, error) {
	req, err := http.NewRequest("GET", resourceURL, nil)
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

	limitedBody := http.MaxBytesReader(nil, resp.Body, 10*1024*1024)
	data, err := io.ReadAll(limitedBody)
	if err != nil {
		return nil, "", err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}

	return data, contentType, nil
}

// Update entry in User map
func updateUserInfo(values interface{}, field string, value string) interface{} {
	log.Debug().Str("field", field).Str("value", value).Msg("User info updated")
	values.(Values).m[field] = value
	return values
}

// webhook for regular messages
func callHook(myurl string, payload map[string]string, id string) {
	log.Info().Str("url", myurl).Msg("Sending POST to client " + id)

	// Log the payload map
	log.Debug().Msg("Payload:")
	for key, value := range payload {
		log.Debug().Str(key, value).Msg("")
	}

	client := clientManager.GetHTTPClient(id)

	// If no HTTP client exists for this userID, create a default one
	if client == nil {
		log.Warn().Str("userID", id).Msg("No HTTP client found, creating default client")
		client = resty.New()
		client.SetTimeout(30 * time.Second)
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		clientManager.SetHTTPClient(id, client)
	}

	format := os.Getenv("WEBHOOK_FORMAT")
	if format == "json" {
		// Send as pure JSON
		// The original payload is a map[string]string, but we want to send the postmap (map[string]interface{})
		// So we try to decode the jsonData field if it exists, otherwise we send the original payload
		var body interface{} = payload
		if jsonStr, ok := payload["jsonData"]; ok {
			var postmap map[string]interface{}
			err := json.Unmarshal([]byte(jsonStr), &postmap)
			if err == nil {
				postmap["token"] = payload["token"]
				body = postmap
			}
		}
		_, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(body).
			Post(myurl)
		if err != nil {
			log.Debug().Str("error", err.Error())
		}
	} else {
		// Default: send as form-urlencoded
		_, err := client.R().SetFormData(payload).Post(myurl)
		if err != nil {
			log.Debug().Str("error", err.Error())
		}
	}
}

// webhook for messages with file attachments
func callHookFile(myurl string, payload map[string]string, id string, file string) error {
	log.Info().Str("file", file).Str("url", myurl).Msg("Sending POST")

	client := clientManager.GetHTTPClient(id)

	// If no HTTP client exists for this userID, create a default one
	if client == nil {
		log.Warn().Str("userID", id).Msg("No HTTP client found, creating default client")
		client = resty.New()
		client.SetTimeout(30 * time.Second)
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		clientManager.SetHTTPClient(id, client)
	}

	// Create final payload map
	finalPayload := make(map[string]string)
	for k, v := range payload {
		finalPayload[k] = v
	}

	finalPayload["file"] = file

	log.Debug().Interface("finalPayload", finalPayload).Msg("Final payload to be sent")

	resp, err := client.R().
		SetFiles(map[string]string{
			"file": file,
		}).
		SetFormData(finalPayload).
		Post(myurl)

	if err != nil {
		log.Error().Err(err).Str("url", myurl).Msg("Failed to send POST request")
		return fmt.Errorf("failed to send POST request: %w", err)
	}

	log.Debug().Interface("payload", finalPayload).Msg("Payload sent to webhook")
	log.Info().Int("status", resp.StatusCode()).Str("body", string(resp.Body())).Msg("POST request completed")

	return nil
}

func (s *server) respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Error().Err(err).Msg("Failed to encode JSON response")
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// ProcessOutgoingMedia handles media processing for outgoing messages with S3 support
func ProcessOutgoingMedia(userID string, contactJID string, messageID string, data []byte, mimeType string, fileName string, db *sqlx.DB) (map[string]interface{}, error) {
	// Check if S3 is enabled for this user
	var s3Config struct {
		Enabled       bool   `db:"s3_enabled"`
		MediaDelivery string `db:"media_delivery"`
	}

	// Use explicit column selection to avoid column count mismatch
	err := db.Get(&s3Config, "SELECT s3_enabled, media_delivery FROM users WHERE id = $1", userID)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to get S3 config")
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

// GenerateAudioWaveformFromOggOpus decodifica um buffer OGG/Opus em PCM via ffmpeg
// e calcula um waveform de 64 amostras (0..100) no mesmo estilo do WhatsApp.
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
