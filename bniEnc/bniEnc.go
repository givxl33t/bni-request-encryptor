package bniEnc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const timeDiffLimit = 480

func Encrypt(json string, clientID string, secretKey string) string {
	return doubleEncrypt(reverse(fmt.Sprintf("%v", time.Now().Unix()))+"."+json, clientID, secretKey)
}

func Decrypt(encrypted string, clientID string, secretKey string) (string, error) {
	parsedString := doubleDecrypt(encrypted, clientID, secretKey)
	parts := strings.SplitN(parsedString, ".", 2)
	if len(parts) < 2 {
		return "", errors.New("bniEnc: parsing error, wrong cid or sck or invalid data.")
	}
	if !timestampIsValid(reverse(parts[0])) {
		return "", errors.New("bniEnc: data has been expired.")
	}
	return parts[1], nil
}

func timestampIsValid(timestamp string) bool {
	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	return math.Abs(float64(parsedTimestamp-time.Now().Unix())) <= timeDiffLimit
}

func doubleEncrypt(value string, clientID string, secretKey string) string {
	result := encrypt([]byte(value), clientID)
	result = encrypt(result, secretKey)
	encoded := base64.StdEncoding.EncodeToString(result)
	return strings.ReplaceAll(strings.ReplaceAll(strings.TrimRight(encoded, "="), "+", "-"), "/", "_")
}

func encrypt(value []byte, key string) []byte {
	result := make([]byte, 0, len(value))
	keyLength := len(key)
	for index, character := range value {
		keyCharacter := key[(index+keyLength-1)%keyLength]
		result = append(result, byte((int(character)+int(keyCharacter))%128))
	}
	return result
}

func doubleDecrypt(value string, clientID string, secretKey string) string {
	if padding := len(value) % 4; padding != 0 {
		value += strings.Repeat("=", 4-padding)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(value, "-", "+"), "_", "/"))
	if err != nil {
		return ""
	}
	decoded = decrypt(decoded, clientID)
	decoded = decrypt(decoded, secretKey)
	return string(decoded)
}

func decrypt(value []byte, key string) []byte {
	result := make([]byte, 0, len(value))
	keyLength := len(key)
	for index, character := range value {
		keyCharacter := key[(index+keyLength-1)%keyLength]
		result = append(result, byte(((int(character)-int(keyCharacter))+256)%128))
	}
	return result
}

func reverse(value string) string {
	characters := []rune(value)
	for left, right := 0, len(characters)-1; left < right; left, right = left+1, right-1 {
		characters[left], characters[right] = characters[right], characters[left]
	}
	return string(characters)
}
