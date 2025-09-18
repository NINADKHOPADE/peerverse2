# PeerSync - Mentorship Platform

## Deployment Instructions

### For Vercel Deployment:

1. **Install Vercel CLI:**
   ```bash
   npm install -g vercel
   ```

2. **Login to Vercel:**
   ```bash
   vercel login
   ```

3. **Deploy:**
   ```bash
   vercel --prod
   ```

### Environment Variables (Set in Vercel Dashboard):

- `DATABASE_URL`: Your PostgreSQL connection string
- `JWT_SECRET`: Your JWT secret key
- `EMAIL_USER`: Gmail address for sending emails
- `EMAIL_PASS`: Gmail app password
- `NODE_ENV`: production

### Mobile Compatibility Features:

- Dynamic port configuration (no fixed port 5000)
- Responsive viewport settings
- Mobile-first CSS design
- Touch-friendly interface elements
- Proper API error handling for mobile networks

### Key Changes Made:

1. **Fixed Vercel Configuration:**
   - Created proper `api/index.js` entry point
   - Updated `vercel.json` with correct build settings
   - Added function timeout and size limits

2. **Mobile Compatibility:**
   - Changed from fixed port 5000 to dynamic port
   - Updated frontend to use `window.location.origin` in production
   - Added mobile-responsive CSS
   - Fixed viewport meta tag

3. **Removed Socket.IO:**
   - Socket.IO doesn't work with Vercel serverless functions
   - Replaced real-time features with polling-based alternatives

4. **API Optimization:**
   - Streamlined API endpoints for serverless deployment
   - Added proper error handling
   - Implemented caching for better performance

### Local Development:

```bash
# Install dependencies
npm install
cd FRONTEND/frontone && npm install

# Start development
npm run dev
```

### Production Build:

```bash
# Build for production
npm run build
```

The application will now work properly on mobile devices and deploy successfully to Vercel without the previous errors.