package credential

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
)

var ErrNotFound = errors.New("dns credential not found")

type Repository interface {
	CreateDNSCredential(context.Context, *Credential, []byte) error
	UpdateDNSCredential(context.Context, *Credential, []byte) error
	DNSCredentials(context.Context) ([]Credential, error)
	DNSCredential(context.Context, string) (Credential, []byte, error)
	DeleteDNSCredential(context.Context, string) error
}

type Service struct {
	store    Repository
	registry *Registry
	cipher   *Cipher
	lookup   func(string) (string, bool)
}

func NewService(store Repository, registry *Registry, cipher *Cipher) *Service {
	return &Service{store: store, registry: registry, cipher: cipher, lookup: os.LookupEnv}
}

func (s *Service) Providers() []Provider { return s.registry.List() }

func (s *Service) Create(ctx context.Context, request CreateRequest) (Credential, error) {
	value, encrypted, err := s.prepare(request)
	if err != nil {
		return Credential{}, err
	}
	if err := s.store.CreateDNSCredential(ctx, &value, encrypted); err != nil {
		return Credential{}, err
	}
	return value, nil
}

func (s *Service) Update(ctx context.Context, id string, request CreateRequest) (Credential, error) {
	value, encrypted, err := s.prepare(request)
	if err != nil {
		return Credential{}, err
	}
	value.ID = strings.TrimSpace(id)
	if err := s.store.UpdateDNSCredential(ctx, &value, encrypted); err != nil {
		return Credential{}, err
	}
	return value, nil
}

func (s *Service) Rename(ctx context.Context, id, name string) (Credential, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return Credential{}, errors.New("DNS 凭据名称长度无效")
	}
	value, encrypted, err := s.store.DNSCredential(ctx, strings.TrimSpace(id))
	if err != nil {
		return Credential{}, err
	}
	value.Name = name
	if err := s.store.UpdateDNSCredential(ctx, &value, encrypted); err != nil {
		return Credential{}, err
	}
	return value, nil
}

func (s *Service) prepare(request CreateRequest) (Credential, []byte, error) {
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 100 {
		return Credential{}, nil, errors.New("DNS 凭据名称长度无效")
	}
	provider, ok := s.registry.Get(request.Provider)
	if !ok {
		return Credential{}, nil, errors.New("不支持的 DNS Provider")
	}
	acmeCode := provider.ACMEDNSCode
	if provider.Custom {
		acmeCode = strings.TrimSpace(request.CustomACMECode)
		if err := ValidateCustomProviderCode(acmeCode); err != nil {
			return Credential{}, nil, err
		}
	}
	value := Credential{Name: request.Name, Provider: provider.Code, ACMEDNSCode: acmeCode, SourceMode: request.SourceMode}
	var encrypted []byte
	switch request.SourceMode {
	case "encrypted":
		if s.cipher == nil {
			return Credential{}, nil, errors.New("DNS 凭据加密服务不可用")
		}
		if err := ValidateValues(provider, request.Values); err != nil {
			return Credential{}, nil, err
		}
		var err error
		encrypted, err = s.cipher.Encrypt(request.Values)
		if err != nil {
			return Credential{}, nil, err
		}
		value.MaskedFields = sortedKeys(request.Values)
	case "environment":
		if len(request.EnvironmentRefs) == 0 {
			return Credential{}, nil, errors.New("环境变量引用不能为空")
		}
		for field, environmentName := range request.EnvironmentRefs {
			if provider.Custom {
				if err := ValidateEnvironmentName(field); err != nil {
					return Credential{}, nil, err
				}
			} else {
				known := false
				for _, definition := range provider.Fields {
					if definition.Name == field {
						known = true
						break
					}
				}
				if !known {
					return Credential{}, nil, errors.New("环境引用包含 Provider 未声明字段")
				}
			}
			if err := ValidateEnvironmentName(environmentName); err != nil {
				return Credential{}, nil, err
			}
		}
		if !provider.Custom {
			for _, field := range provider.Fields {
				if field.Required && strings.TrimSpace(request.EnvironmentRefs[field.Name]) == "" {
					return Credential{}, nil, errors.New("缺少必填 DNS 凭据环境引用")
				}
			}
		}
		value.EnvironmentRefs = request.EnvironmentRefs
		value.MaskedFields = sortedKeys(request.EnvironmentRefs)
	default:
		return Credential{}, nil, errors.New("DNS 凭据来源模式无效")
	}
	return value, encrypted, nil
}

func (s *Service) List(ctx context.Context) ([]Credential, error) {
	return s.store.DNSCredentials(ctx)
}

func (s *Service) Get(ctx context.Context, id string) (Credential, error) {
	value, _, err := s.store.DNSCredential(ctx, id)
	return value, err
}

func (s *Service) Resolve(ctx context.Context, id string) (ProcessValues, error) {
	value, encrypted, err := s.store.DNSCredential(ctx, id)
	if err != nil {
		return ProcessValues{}, err
	}
	var environment map[string]string
	switch value.SourceMode {
	case "encrypted":
		environment, err = s.cipher.Decrypt(encrypted)
		if err != nil {
			return ProcessValues{}, err
		}
	case "environment":
		environment = make(map[string]string, len(value.EnvironmentRefs))
		for field, environmentName := range value.EnvironmentRefs {
			resolved, ok := s.lookup(environmentName)
			if !ok || resolved == "" {
				return ProcessValues{}, errors.New("DNS 凭据引用的环境变量未配置")
			}
			environment[field] = resolved
		}
	default:
		return ProcessValues{}, errors.New("DNS 凭据来源模式无效")
	}
	return ProcessValues{ACMEDNSCode: value.ACMEDNSCode, Environment: environment}, nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.DeleteDNSCredential(ctx, id)
}

func (s *Service) Test(ctx context.Context, id string) error {
	values, err := s.Resolve(ctx, id)
	for key := range values.Environment {
		values.Environment[key] = ""
		delete(values.Environment, key)
	}
	return err
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
