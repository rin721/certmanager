package credential

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

type Field struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
	Placeholder string `json:"placeholder,omitempty"`
	Description string `json:"description,omitempty"`
}

type Provider struct {
	Code              string  `json:"provider_code"`
	DisplayName       string  `json:"display_name"`
	ACMEDNSCode       string  `json:"acme_dns_code"`
	Fields            []Field `json:"fields"`
	DocumentationHint string  `json:"documentation_hint"`
	Custom            bool    `json:"custom"`
}

type Registry struct {
	providers map[string]Provider
}

func NewRegistry() *Registry {
	values := []Provider{
		{Code: "cloudflare", DisplayName: "Cloudflare", ACMEDNSCode: "dns_cf", DocumentationHint: "推荐使用仅具 DNS 编辑权限的 API Token。", Fields: []Field{
			{Name: "CF_Token", Label: "API Token", Required: true, Secret: true},
			{Name: "CF_Zone_ID", Label: "Zone ID", Secret: true, Description: "可选；限制到单个 Zone。"},
			{Name: "CF_Account_ID", Label: "Account ID", Secret: true, Description: "多账户场景可选。"},
		}},
		{Code: "alidns", DisplayName: "阿里云 DNS", ACMEDNSCode: "dns_ali", Fields: []Field{
			{Name: "Ali_Key", Label: "AccessKey ID", Required: true, Secret: true},
			{Name: "Ali_Secret", Label: "AccessKey Secret", Required: true, Secret: true},
		}},
		{Code: "dnspod", DisplayName: "腾讯云 DNSPod", ACMEDNSCode: "dns_dp", Fields: []Field{
			{Name: "DP_Id", Label: "API ID", Required: true, Secret: true},
			{Name: "DP_Key", Label: "API Token", Required: true, Secret: true},
		}},
		{Code: "route53", DisplayName: "AWS Route 53", ACMEDNSCode: "dns_aws", Fields: []Field{
			{Name: "AWS_ACCESS_KEY_ID", Label: "Access Key ID", Required: true, Secret: true},
			{Name: "AWS_SECRET_ACCESS_KEY", Label: "Secret Access Key", Required: true, Secret: true},
			{Name: "AWS_SESSION_TOKEN", Label: "Session Token", Secret: true},
		}},
		{Code: "huaweicloud", DisplayName: "华为云 DNS", ACMEDNSCode: "dns_huaweicloud", Fields: []Field{
			{Name: "HUAWEICLOUD_Username", Label: "IAM 用户名", Required: true, Secret: true},
			{Name: "HUAWEICLOUD_Password", Label: "IAM 密码", Required: true, Secret: true},
			{Name: "HUAWEICLOUD_DomainName", Label: "账户名", Required: true, Secret: false},
			{Name: "HUAWEICLOUD_Region", Label: "区域", Required: true, Secret: false},
		}},
		{Code: "custom", DisplayName: "自定义 Provider", Custom: true, DocumentationHint: "仅允许 acme.sh 已安装的 dns_* Provider 和受控环境变量。"},
	}
	registry := &Registry{providers: make(map[string]Provider, len(values))}
	for _, value := range values {
		registry.providers[value.Code] = value
	}
	return registry
}

func (r *Registry) List() []Provider {
	values := make([]Provider, 0, len(r.providers))
	for _, value := range r.providers {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].DisplayName < values[j].DisplayName })
	return values
}

func (r *Registry) Get(code string) (Provider, bool) {
	value, ok := r.providers[code]
	return value, ok
}

var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var processEnvironmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var providerCodePattern = regexp.MustCompile(`^dns_[a-z0-9_]+$`)

var forbiddenEnvironmentNames = map[string]struct{}{
	"PATH": {}, "HOME": {}, "SHELL": {}, "LD_PRELOAD": {}, "LD_LIBRARY_PATH": {}, "GODEBUG": {},
	"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {}, "APP_ENCRYPTION_KEY": {}, "ADMIN_PASSWORD": {}, "SESSION_SECRET": {},
}

func ValidateEnvironmentName(name string) error {
	if !environmentNamePattern.MatchString(name) {
		return errors.New("环境变量名称格式无效")
	}
	if _, forbidden := forbiddenEnvironmentNames[strings.ToUpper(name)]; forbidden {
		return errors.New("环境变量名称禁止覆盖系统或应用敏感配置")
	}
	return nil
}

func ValidateProcessEnvironmentName(name string) error {
	if !processEnvironmentNamePattern.MatchString(name) {
		return errors.New("环境变量名称格式无效")
	}
	if _, forbidden := forbiddenEnvironmentNames[strings.ToUpper(name)]; forbidden {
		return errors.New("环境变量名称禁止覆盖系统或应用敏感配置")
	}
	return nil
}

func ValidateCustomProviderCode(code string) error {
	if !providerCodePattern.MatchString(code) {
		return errors.New("acme.sh DNS Provider Code 必须匹配 dns_[a-z0-9_]+")
	}
	return nil
}

func ValidateValues(provider Provider, values map[string]string) error {
	if provider.Custom {
		for name, value := range values {
			if err := ValidateEnvironmentName(name); err != nil {
				return err
			}
			if value == "" {
				return errors.New("凭据值不能为空")
			}
		}
		return nil
	}
	allowed := make(map[string]Field, len(provider.Fields))
	for _, field := range provider.Fields {
		allowed[field.Name] = field
		if field.Required && strings.TrimSpace(values[field.Name]) == "" {
			return errors.New("缺少必填 DNS 凭据字段")
		}
	}
	for name := range values {
		if _, ok := allowed[name]; !ok {
			return errors.New("DNS 凭据包含 Provider 未声明字段")
		}
	}
	return nil
}
