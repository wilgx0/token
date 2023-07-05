package token

type Config struct {
	SigningKey    string `json:"signingKey"`    // jwt签名
	ExpiresTime   int64  `json:"expiresTime"`   // 过期时间
	BufferTime    int64  `json:"bufferTime"`    // 缓冲时间
	Issuer        string `json:"issuer"`        // 签发者
	UseMultipoint bool   `json:"useMultipoint"` // 多点登录拦截
}
