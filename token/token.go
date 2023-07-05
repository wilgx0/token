package token

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
	"time"
)

type JWT struct {
	Config       Config
	singleflight *singleflight.Group
}

func New(opts ...Option) *JWT {
	j := &JWT{
		singleflight: &singleflight.Group{},
	}
	for _, opt := range opts {
		opt(j)
	}
	return j
}

func (j *JWT) CreateClaims(userInfo interface{}) CustomClaims {
	claims := CustomClaims{
		UserInfo:   userInfo,
		BufferTime: j.Config.BufferTime,
		RegisteredClaims: jwt.RegisteredClaims{
			NotBefore: jwt.NewNumericDate(time.Unix(time.Now().Unix()-1000, 0)),                 // 签名生效时间
			ExpiresAt: jwt.NewNumericDate(time.Unix(time.Now().Unix()+j.Config.ExpiresTime, 0)), // 过期时间
			Issuer:    j.Config.Issuer,                                                          // 签名的发行者
		},
	}
	return claims
}

// 生成token
func (j *JWT) CreateToken(claims CustomClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.Config.SigningKey))
}

// 刷新token （旧token换新token,且使用归并回源避免并发问题）
func (j *JWT) RefreshToken(oldToken string, oldClaims CustomClaims) (newToken string, err error) {
	oldClaims.ExpiresAt = jwt.NewNumericDate(time.Unix(time.Now().Unix()+j.Config.ExpiresTime, 0))
	v, err, _ := j.singleflight.Do("JWT:"+oldToken, func() (interface{}, error) {
		return j.CreateToken(oldClaims)
	})
	return v.(string), err
}

// 解析token
func (j *JWT) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.Config.SigningKey), nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}

type CustomClaims struct {
	UserInfo
	BufferTime int64
	jwt.RegisteredClaims
}

func (c CustomClaims) Validate() error {
	if c.UserInfo == nil {
		return errors.New("must be userInfo")
	}
	return nil
}

// 是否需要刷新token
func (c CustomClaims) IsRefresh() bool {
	return c.ExpiresAt.Unix()-time.Now().Unix() < c.BufferTime
}

type UserInfo interface{}
