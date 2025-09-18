@echo off
echo Installing Backend Dependencies...
cd BACKEND
npm install

echo.
echo Installing Frontend Dependencies...
cd ..\FRONTEND\frontone
npm install

echo.
echo Installation Complete!
echo.
echo To start the application:
echo 1. Start Backend: cd BACKEND && npm run dev
echo 2. Start Frontend: cd FRONTEND\frontone && npm start
echo.
pause