# Sahayak Controlled-Pilot Infrastructure

This stack provisions the approved single-node pilot topology:

- Azure Central India resource group, VNet, NSG, static outbound IP, and B2ats_v2 Linux VM.
- Cloudflare remotely managed Tunnel and proxied `sahayak.dagzer.com` DNS record.
- Private Cloudflare R2 bucket for encrypted backups and media.
- Azure monthly budget notifications.
- Hardened VM bootstrap with Docker, log rotation, unattended updates, swap, firewall, and no public application ports.

The VM is intentionally not highly available. PostgreSQL, PostGIS, API, and worker run on the same node during the controlled pilot. The selected B2ats_v2 SKU provides 2 vCPU and 1 GiB RAM, is available to the selected subscription in Central India, and is included in Azure's 12-month free-service list when the subscription is eligible. The documented upgrade path moves PostgreSQL to Flexible Server and application workloads to Container Apps when measured thresholds require it.

The `Test NVIDIA` subscription currently reports the standard Pay-As-You-Go quota with spending limits disabled. The plan therefore assumes full retail billing rather than free-service eligibility: approximately `$4.49` VM compute, `$2.64` E4 SSD, and `$4.38` Standard IPv4 per month, totaling `$11.51` before tax and variable egress. Cloudflare Tunnel, proxied DNS, TLS, and the first 10 GB-month of R2 Standard storage are expected to remain free at pilot usage. The Azure budget is `$15`, with an actual-usage alert near `$12` and a forecast alert at `$15`; Azure budgets notify but do not stop resources automatically.

## Phase 1: Authentication

The validated toolchain is pinned to:

- Terraform `1.16.0`
- Azure CLI `2.90.0`
- AzureRM provider `4.81.0`
- Cloudflare provider `5.24.0`
- cloudflared `2026.8.3`

Mutable `latest` tags are not used by deployment commands. Digests and the Terraform provider lock file make the deployment reproducible.

Authenticate Azure with the containerized CLI:

```bash
docker run --rm -it \
  -v /tmp/kilo/azure-config:/root/.azure \
  mcr.microsoft.com/azure-cli@sha256:e3768dde8142efa45d8f356a317aaac77abd7da15ba3719b0a150e9453f251db \
  az login --use-device-code
```

Complete the browser/device-code flow without closing the terminal. Then list subscriptions:

Run Azure CLI commands sequentially. Multiple containers must not write to the same `/tmp/kilo/azure-config` directory concurrently.

```bash
docker run --rm \
  -v /tmp/kilo/azure-config:/root/.azure \
  mcr.microsoft.com/azure-cli@sha256:e3768dde8142efa45d8f356a317aaac77abd7da15ba3719b0a150e9453f251db \
  az account list --output table
```

Select the intended subscription:

```bash
docker run --rm \
  -v /tmp/kilo/azure-config:/root/.azure \
  mcr.microsoft.com/azure-cli@sha256:e3768dde8142efa45d8f356a317aaac77abd7da15ba3719b0a150e9453f251db \
  az account set --subscription "YOUR_SUBSCRIPTION_ID"
```

Build the pinned local Terraform runner. It contains the same Azure CLI used for login, so no service-principal secret is required:

```bash
docker build \
  --file deploy/terraform/Dockerfile.tooling \
  --tag sahayak-terraform-tooling:1.16.0 \
  deploy/terraform
```

The runner reuses `/tmp/kilo/azure-config`; keep the Azure login active and do not copy its files into the repository.

Create a Cloudflare API token with only:

- Account: Cloudflare Tunnel Edit
- Zone: DNS Edit for `dagzer.com`
- Account: Workers R2 Storage Edit

In Cloudflare Dashboard, open **My Profile → API Tokens → Create Token → Custom token**. Restrict account resources to the Dagzer account and zone resources to `dagzer.com`.

Export it without saving it in a file:

```bash
read -rsp "Cloudflare API token: " CLOUDFLARE_API_TOKEN
export CLOUDFLARE_API_TOKEN
```

Copy the Account ID from the dashboard overview and the Zone ID from the `dagzer.com` overview into `terraform.tfvars`. Cloudflare does not provide an interactive Terraform login; the scoped API token is its supported provider authentication method.

## Phase 2: Local Inputs

```bash
cd deploy/terraform/pilot
cp terraform.tfvars.example terraform.tfvars
chmod 600 terraform.tfvars
```

Replace IDs, SSH key, and alert email. Never commit `terraform.tfvars`.

## Phase 3: Validation And Plan

```bash
TF_IMAGE=sahayak-terraform-tooling:1.16.0
TF_DIR="$PWD"

docker run --rm \
  -e CLOUDFLARE_API_TOKEN \
  -v /tmp/kilo/azure-config:/root/.azure \
  -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" init

docker run --rm -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" fmt -check
docker run --rm -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" validate

docker run --rm \
  -e CLOUDFLARE_API_TOKEN \
  -v /tmp/kilo/azure-config:/root/.azure \
  -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" plan -out=pilot.tfplan

docker run --rm -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" show pilot.tfplan
```

Review every resource and the fixed monthly estimate before applying. Do not use `-auto-approve`.

## Phase 4: Apply

```bash
docker run --rm \
  -e CLOUDFLARE_API_TOKEN \
  -v /tmp/kilo/azure-config:/root/.azure \
  -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" apply pilot.tfplan
```

Application deployment and production secrets are intentionally separate from infrastructure state. Terraform does not receive Meta, Razorpay, encryption-key, database-password, R2-secret, or Sentry credentials.

## Rollback

Export required encrypted backups before destroying infrastructure, then run:

```bash
docker run --rm \
  -e CLOUDFLARE_API_TOKEN \
  -v /tmp/kilo/azure-config:/root/.azure \
  -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" plan -destroy -out=destroy.tfplan
docker run --rm -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" show destroy.tfplan
docker run --rm \
  -e CLOUDFLARE_API_TOKEN \
  -v /tmp/kilo/azure-config:/root/.azure \
  -v "$TF_DIR:/workspace" -w /workspace "$TF_IMAGE" apply destroy.tfplan
```

Cloudflare provider `5.24.0` currently warns that remotely managed Tunnel configuration and R2 lifecycle configuration cannot be deleted by Terraform. After a destroy, remove those two configurations from the Cloudflare dashboard before deleting the Tunnel or bucket. DNS, Tunnel, bucket, Azure VM, disk, IP, networking, budget, and resource group remain represented in the Terraform state.
