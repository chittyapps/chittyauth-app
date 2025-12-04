# GitHub Actions Setup Guide

This guide explains how to configure GitHub Actions for automated deployment of ChittyAuth App.

## 🎯 Overview

The repository includes two GitHub Actions workflows:

1. **Production Deployment** (`.github/workflows/deploy-production.yml`)
   - Triggers on push to `main` branch
   - Runs tests first
   - Deploys to `https://auth.chitty.cc`
   - Can be manually triggered

2. **Development Deployment** (`.github/workflows/deploy-development.yml`)
   - Triggers on push to `develop`, `dev`, or `staging` branches
   - Runs tests on all PRs to `main`
   - Deploys to `https://dev.auth.chitty.cc`
   - Can be manually triggered

---

## 🔐 Required GitHub Secrets

You need to configure the following secrets in your GitHub repository:

### 1. CLOUDFLARE_API_TOKEN

**What it is:** API token for Cloudflare Workers deployment

**How to get it:**
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Click "Create Token"
3. Use the "Edit Cloudflare Workers" template
4. Configure permissions:
   - Account → Cloudflare Workers Scripts → Edit
   - Account → Account Settings → Read
   - Zone → Workers Routes → Edit (if using custom domains)
5. Click "Continue to summary" → "Create Token"
6. Copy the token (you'll only see it once!)

**Add to GitHub:**
```bash
# Navigate to your repo on GitHub:
# Settings → Secrets and variables → Actions → New repository secret
# Name: CLOUDFLARE_API_TOKEN
# Value: <paste your token>
```

### 2. CLOUDFLARE_ACCOUNT_ID

**What it is:** Your Cloudflare account ID

**How to get it:**
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Select any domain/worker
3. Look in the URL or right sidebar for "Account ID"
4. For ChittyCorp: `0bc21e3a5a9de1a4cc843be9c3e98121`

**Add to GitHub:**
```bash
# Settings → Secrets and variables → Actions → New repository secret
# Name: CLOUDFLARE_ACCOUNT_ID
# Value: 0bc21e3a5a9de1a4cc843be9c3e98121
```

---

## ⚙️ Optional: Environment-Specific Secrets

If you want to use different Cloudflare accounts for production and development:

### Production Environment
1. Go to: Settings → Environments → New environment
2. Name: `production`
3. Add environment secrets:
   - `CLOUDFLARE_API_TOKEN` (production-specific)
   - `CLOUDFLARE_ACCOUNT_ID` (production account)

### Development Environment
1. Go to: Settings → Environments → New environment
2. Name: `development`
3. Add environment secrets:
   - `CLOUDFLARE_API_TOKEN` (dev-specific)
   - `CLOUDFLARE_ACCOUNT_ID` (dev account)

---

## 🚀 Quick Setup Steps

### Step 1: Add Secrets to GitHub

1. Go to your repository on GitHub
2. Navigate to: **Settings** → **Secrets and variables** → **Actions**
3. Click **"New repository secret"**
4. Add both secrets:
   - `CLOUDFLARE_API_TOKEN`
   - `CLOUDFLARE_ACCOUNT_ID`

### Step 2: Verify Workflow Files

Ensure these files exist:
```
.github/
├── workflows/
│   ├── deploy-production.yml
│   └── deploy-development.yml
└── SETUP.md (this file)
```

### Step 3: Test the Workflow

**Option A: Push to main (auto-deploy)**
```bash
git checkout main
git add .
git commit -m "Add GitHub Actions workflows"
git push origin main
```

**Option B: Manual trigger**
1. Go to: **Actions** tab on GitHub
2. Select "Deploy to Production"
3. Click "Run workflow"
4. Select branch: `main`
5. Click "Run workflow"

### Step 4: Monitor Deployment

1. Go to: **Actions** tab
2. Click on the running workflow
3. Watch the deployment progress
4. Verify health check passes

---

## 📋 Workflow Behavior

### Production Workflow (`main` branch)

```
1. Trigger (push to main)
   ↓
2. Run Tests (npm test)
   ↓
3. Deploy to Production (wrangler deploy --env production)
   ↓
4. Verify Deployment (curl health endpoint)
   ↓
5. Notify Status (success/failure)
```

**When it runs:**
- ✅ Push to `main` branch
- ✅ Manual trigger via GitHub UI

**What it deploys:**
- 🌐 Production: `https://auth.chitty.cc`

### Development Workflow (`develop` branch)

```
1. Trigger (push to develop or PR to main)
   ↓
2. Run Tests (npm test)
   ↓
3. Deploy to Development (wrangler deploy --env development)
   ↓
4. Verify Deployment (curl health endpoint)
```

**When it runs:**
- ✅ Push to `develop`, `dev`, or `staging` branch
- ✅ Pull request to `main` (tests only, no deploy)
- ✅ Manual trigger via GitHub UI

**What it deploys:**
- 🌐 Development: `https://dev.auth.chitty.cc`

---

## 🛡️ Security Best Practices

1. **Never commit secrets to code**
   - Always use GitHub Secrets
   - Secrets are encrypted and masked in logs

2. **Use environment protection rules**
   - Settings → Environments → `production`
   - Enable "Required reviewers"
   - Add deployment branch restrictions

3. **Rotate API tokens regularly**
   - Generate new Cloudflare API token quarterly
   - Update GitHub secret
   - Revoke old token

4. **Limit token permissions**
   - Only grant "Edit Cloudflare Workers" permission
   - Don't use tokens with full account access

---

## 🐛 Troubleshooting

### Error: "Authentication error"

**Cause:** `CLOUDFLARE_API_TOKEN` is missing or invalid

**Solution:**
1. Verify secret is set: Settings → Secrets → `CLOUDFLARE_API_TOKEN`
2. Generate new token from Cloudflare Dashboard
3. Update GitHub secret

### Error: "Account ID not found"

**Cause:** `CLOUDFLARE_ACCOUNT_ID` is missing or wrong

**Solution:**
1. Get correct account ID from Cloudflare Dashboard
2. Update GitHub secret: `CLOUDFLARE_ACCOUNT_ID`

### Error: "Tests failed"

**Cause:** Tests are failing on CI

**Solution:**
1. Run tests locally: `npm test`
2. Fix failing tests
3. Push fix to repository

### Error: "wrangler.toml not found"

**Cause:** Deployment can't find configuration

**Solution:**
1. Ensure `wrangler.toml` exists in repository root
2. Check file is committed to git
3. Verify workflow `uses: actions/checkout@v4` step runs

### Deployment succeeds but health check fails

**Cause:** DNS propagation or service startup delay

**Solution:**
- This is usually fine - the service takes time to propagate
- Check manually after 30 seconds: `curl https://auth.chitty.cc/health`
- Verify in Cloudflare Dashboard → Workers

---

## 🧪 Testing Workflows Locally

You can test workflow syntax without pushing:

```bash
# Install act (https://github.com/nektos/act)
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run workflow locally
act -j test  # Run test job only
act -j deploy --secret-file .secrets  # Run deploy with secrets
```

**Note:** Full deployment testing requires valid Cloudflare credentials.

---

## 📊 Monitoring Deployments

### View Deployment History

1. Go to: **Actions** tab
2. Filter by workflow name
3. Click any run to see details

### View Deployment Status

1. Go to: **Environments** (in repo sidebar)
2. Click `production` or `development`
3. See deployment history and status

### Live Logs

```bash
# Stream production logs
wrangler tail --env production

# Stream development logs
wrangler tail --env development
```

---

## 🔄 Rollback Procedure

If a deployment fails:

### Via Cloudflare Dashboard
1. Go to Workers → `chittyauth-app`
2. Click "Deployments" tab
3. Find previous working deployment
4. Click "Rollback"

### Via GitHub Actions
1. Go to: Actions → Deploy to Production
2. Find last successful deployment
3. Click "Re-run all jobs"

---

## ✅ Verification Checklist

After setup, verify:

- [ ] `CLOUDFLARE_API_TOKEN` secret is set
- [ ] `CLOUDFLARE_ACCOUNT_ID` secret is set
- [ ] Workflow files exist in `.github/workflows/`
- [ ] Production workflow triggers on push to `main`
- [ ] Development workflow triggers on push to `develop`
- [ ] Tests run before deployment
- [ ] Health check passes after deployment
- [ ] Deployment status shows in Environments tab

---

## 📞 Support

**GitHub Actions Issues:**
- Check workflow logs in Actions tab
- Verify secrets are set correctly
- Ensure wrangler.toml is configured

**Cloudflare Deployment Issues:**
- Check Cloudflare Dashboard → Workers
- Run `wrangler whoami` locally to verify auth
- Review wrangler.toml bindings (D1, KV)

**Need Help?**
- Create an issue in the repository
- Check [GitHub Actions documentation](https://docs.github.com/en/actions)
- Check [Wrangler Action documentation](https://github.com/cloudflare/wrangler-action)

---

## 🎉 You're All Set!

Your repository now has automated CI/CD with GitHub Actions.

**Next steps:**
1. Push to `main` to trigger production deployment
2. Monitor the Actions tab to see deployment progress
3. Verify service is live: `curl https://auth.chitty.cc/health`
4. Enjoy automated deployments! 🚀
