# Holbertonschool.com – Reconnaissance Report

## 1. IP Ranges (WHOIS)

The domain `holbertonschool.com` is hosted across multiple providers and CDNs.

### IP ranges:

- Webflow infrastructure:
  - 198.202.211.0/24

- AWS / Amazon EC2 ranges:
  - 13.36.0.0/16
  - 13.38.0.0/16
  - 18.202.0.0/16
  - 34.203.0.0/16
  - 35.180.0.0/16
  - 52.47.0.0/16
  - 54.86.0.0/16
  - 54.157.0.0/16
  - 54.155.0.0/16
  - 54.89.0.0/16

- Cloudflare / CDN fronting:
  - 104.16.0.0/12 (Cloudflare)
  - 192.0.78.0/24 (WordPress.com)

## 2. Subdomains & Hosting Infrastructure

Multiple subdomains are exposed with different technologies:

### AWS / Nginx services
- v1, v2, v3.holbertonschool.com
- staging-apply-forum.holbertonschool.com
- yriry2.holbertonschool.com
- smile2021.holbertonschool.com

### Cloudflare-protected services
- support.holbertonschool.com
- help.holbertonschool.com
- en.fr.holbertonschool.com
- fr.webflow.holbertonschool.com

### Webflow / CDN assets
- assets.holbertonschool.com
- rails-assets.holbertonschool.com
- webflow.holbertonschool.com

### WordPress platform
- blog.holbertonschool.com

## 3. Technologies & Frameworks

### Web servers
- Nginx (majority of endpoints)
- Amazon CloudFront
- Cloudflare reverse proxy

### Application frameworks / platforms
- WordPress (blog.holbertonschool.com)
- Webflow (main site hosting)
- Amazon S3 (asset hosting)

### Security & protection layers
- Cloudflare WAF detected on multiple subdomains
- Amazon CloudFront protection on assets and staging services

## 4. Security Observations (WAF)

### WAF Detection Results (wafw00f)

- Cloudflare WAF:
  - www.holbertonschool.com
  - support.holbertonschool.com
  - assets.holbertonschool.com

- Amazon CloudFront WAF:
  - staging-rails-assets-apply.holbertonschool.com

- No WAF detected:
  - blog.holbertonschool.com (WordPress-based filtering instead)

## 5. Summary

- Infrastructure is distributed across AWS, Cloudflare, Webflow, and WordPress
- Strong use of CDN and WAF protection (Cloudflare + CloudFront)
- Large attack surface due to many subdomains and staging environments
- Multiple misconfigured or unreachable subdomains increase recon visibility
