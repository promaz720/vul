# Deployment Guide for Render

## Prerequisites
- Git repository with your code pushed to GitHub
- Render account (free or paid plan)

## Steps to Deploy on Render

### 1. Push Your Code to GitHub
```bash
git init
git add .
git commit -m "Initial commit: Vulnerability Scanner"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
git push -u origin main
```

### 2. Create a Web Service on Render

1. Go to [render.com](https://render.com)
2. Sign in to your Render account
3. Click **"New +"** → **"Web Service"**
4. Connect your GitHub repository
5. Fill in the service details:
   - **Name**: `vulnerability-scanner`
   - **Environment**: `Python`
   - **Region**: Choose your closest region
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Plan**: Select Free or Starter (Free tier has limitations)

### 3. Environment Variables (Optional)
Add these environment variables in Render dashboard:
```
FLASK_ENV = production
PYTHON_VERSION = 3.11
```

### 4. Deploy
Once configured, Render will automatically deploy your application. You'll receive a URL like:
```
https://vulnerability-scanner-xxxxx.onrender.com
```

## Important Notes

### Free Plan Limitations on Render:
- Application spins down after 15 minutes of inactivity (cold start)
- First request after spin-down may take 30+ seconds
- Limited to 1 concurrent connection (for free tier)
- 0.5GB RAM

### Deployment Best Practices:
1. ✅ **Use Gunicorn** - Don't use Flask development server in production
2. ✅ **Set FLASK_ENV=production** - Disables debug mode
3. ✅ **Use environment variables** - For sensitive configuration
4. ✅ **Monitor logs** - Check Render logs for errors
5. ✅ **Test locally first** - Before pushing to production

### Accessing Your Deployment:
- Public URL: `https://vulnerability-scanner-xxxxx.onrender.com`
- View logs: Render Dashboard → Web Service → Logs
- Redeploy: Push to GitHub or manually trigger in Render dashboard

### Troubleshooting

**Issue: Application won't start**
- Check build logs in Render dashboard
- Verify all dependencies in `requirements.txt`
- Ensure `Procfile` is correctly formatted

**Issue: Slow response times**
- Normal on free tier due to cold starts
- Upgrade to Starter plan for always-on service
- Use services like [Pingdom](https://www.pingdom.com) to keep service warm

**Issue: Port errors**
- Ensure `app.run()` uses `port=int(os.getenv("PORT", 5000))`
- Render assigns port dynamically via PORT environment variable

## File Summary

- `Procfile` - Tells Render how to start the application
- `render.yaml` - Alternative Render configuration (optional)
- `requirements.txt` - Python dependencies including gunicorn
- `.gitignore` - Excludes unnecessary files from Git
- `app.py` - Updated for production environment

## Support
- Render Docs: https://render.com/docs
- Flask Docs: https://flask.palletsprojects.com
- Gunicorn Docs: https://docs.gunicorn.org
