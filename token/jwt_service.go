package token

import (
	"time"
)

/*
*
拦截器逻辑：
1、获取token
2、token在黑名单中则终止流程(调用IJwtService.IsBlacklist)
3、解析token，出错则终止流程
4、token快要过期时开始刷新token:

	1、将刷新后的token及过期时间加入到返回头中,例如"new-token"、"new-expires-at"
	2、假如多点拦截（UseMultipoint）为true，则进入多点拦截流程：(用户在登录时也需要走一遍下面这套流程)
		1、调用IJwtService.GetJwt获取用户的旧token
		2、调用IJwtService.InBlackList将旧token加入黑名单
		3、调用IJwtService.SetJwt记录用户最新的一个token

5、记录claims，拦截器流程结束。
*/
type IBlacklist interface {
	IsBlacklist(token string) bool
	InBlackList(token string) error
	GetJwt(userKey string) (token string, err error) // userKey用户唯一标识，例如用户ID或登录账号等
	SetJwt(userKey string, token string, expiration time.Duration) error
}

type JwtService struct {
	BlackList IBlacklist
}

func NewJwtService(opts ...OptionJwtService) *JwtService {
	j := &JwtService{}
	for _, opt := range opts {
		opt(j)
	}
	return j
}

type OptionJwtService func(*JwtService)

func WithBlackList(blackList IBlacklist) OptionJwtService {
	return func(jwt *JwtService) {
		jwt.BlackList = blackList
	}
}

// 多点拦截流程: 旧token进入黑名单，记录新token
func (j *JwtService) UseMultipoint(userKey string, newToken string, expiration time.Duration) (err error) {
	oldToken, err := j.BlackList.GetJwt(userKey)
	if err == nil && oldToken != "" {
		_ = j.BlackList.InBlackList(oldToken)
	}
	_ = j.BlackList.SetJwt(userKey, newToken, expiration)
	return
}
