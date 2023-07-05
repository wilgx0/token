package token

type Option func(*JWT)

func WithOption(config Config) Option {
	return func(jwt *JWT) {
		jwt.Config = config
	}
}
