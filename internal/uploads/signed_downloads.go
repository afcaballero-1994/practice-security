package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(payload [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != 64 {
		return false
	}
	proSign, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil || expires <= now.Unix() {
		return false
	}
	actual := signDownload(payload, fileID, expires)
	actualSig, err := hex.DecodeString(actual)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(actualSig, proSign) == 1
}

func signDownload(key [32]byte, fileID, expires int64) string {
	payload := fmt.Sprintf("GET\n/files/%d/signed-download\n%d", fileID, expires)
	
	mc := hmac.New(sha256.New, key[:])
	mc.Write([]byte(payload))
	output := hex.EncodeToString(mc.Sum(nil))

	return output
}
