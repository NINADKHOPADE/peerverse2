const config = {
  API_BASE_URL: process.env.NODE_ENV === 'production' 
    ? 'https://your-backend-url.vercel.app' 
    : 'http://localhost:5000'
};

export default config;