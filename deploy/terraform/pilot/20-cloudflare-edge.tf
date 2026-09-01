resource "cloudflare_zero_trust_tunnel_cloudflared" "application" {
  account_id = var.cloudflare_account_id
  name       = "${var.resource_prefix}-tunnel"
  config_src = "cloudflare"
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "application" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.application.id
}

resource "cloudflare_dns_record" "application" {
  zone_id = var.cloudflare_zone_id
  name    = var.cloudflare_record_name
  content = "${cloudflare_zero_trust_tunnel_cloudflared.application.id}.cfargotunnel.com"
  type    = "CNAME"
  ttl     = 1
  proxied = true
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "application" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.application.id
  config = {
    ingress = [
      {
        hostname = "${var.cloudflare_record_name}.${var.cloudflare_zone_name}"
        service  = "http://localhost:8080"
      },
      {
        service = "http_status:404"
      }
    ]
  }
}

resource "cloudflare_r2_bucket" "private" {
  account_id    = var.cloudflare_account_id
  name          = var.r2_bucket_name
  location      = "APAC"
  storage_class = "Standard"
}

resource "cloudflare_r2_bucket_lifecycle" "private" {
  account_id  = var.cloudflare_account_id
  bucket_name = cloudflare_r2_bucket.private.name

  rules = [
    {
      id      = "expire-daily-backups"
      enabled = true
      conditions = {
        prefix = "backups/daily/"
      }
      delete_objects_transition = {
        condition = {
          type    = "Age"
          max_age = 691200
        }
      }
    },
    {
      id      = "expire-weekly-backups"
      enabled = true
      conditions = {
        prefix = "backups/weekly/"
      }
      delete_objects_transition = {
        condition = {
          type    = "Age"
          max_age = 3110400
        }
      }
    },
    {
      id      = "abort-incomplete-uploads"
      enabled = true
      conditions = {
        prefix = ""
      }
      abort_multipart_uploads_transition = {
        condition = {
          type    = "Age"
          max_age = 86400
        }
      }
    }
  ]
}
