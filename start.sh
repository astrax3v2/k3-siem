#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

echo ""
echo -e "${BOLD}${BLUE}  🛡️  K3 SIEM Platform v2.4.1${NC}"
echo ""

# Check Node.js version
NODE_VER=$(node -v 2>/dev/null | sed 's/v//' | cut -d. -f1)
if [ -z "$NODE_VER" ]; then
  echo -e "${RED}❌ Node.js not found. Please install Node.js >= 18 from https://nodejs.org${NC}"
  exit 1
fi
if [ "$NODE_VER" -lt 18 ]; then
  echo -e "${RED}❌ Node.js v${NODE_VER} found. Please upgrade to >= 18 (v22 recommended for built-in SQLite)${NC}"
  exit 1
fi
echo -e "${GREEN}✅ Node.js v$(node -v | sed 's/v//')${NC}"

# Check if node:sqlite is available (Node 22+)
SQLITE_FLAG=""
node --experimental-sqlite -e "require('node:sqlite')" 2>/dev/null && SQLITE_FLAG="--experimental-sqlite" || true
if [ -z "$SQLITE_FLAG" ]; then
  echo -e "${YELLOW}⚠  Node < 22 detected — node:sqlite not available. Upgrade to Node 22 for built-in SQLite.${NC}"
  exit 1
fi
echo -e "${GREEN}✅ node:sqlite available${NC}"

# Install backend deps
echo ""
echo -e "${YELLOW}📦 Installing backend dependencies...${NC}"
cd backend && npm install --silent 2>&1 | tail -2
echo -e "${GREEN}✅ Backend dependencies installed${NC}"
cd ..

# Install frontend deps
echo -e "${YELLOW}📦 Installing frontend dependencies...${NC}"
cd frontend && npm install --silent 2>&1 | tail -2
echo -e "${GREEN}✅ Frontend dependencies installed${NC}"
cd ..

# Seed database if needed
if [ ! -f "backend/data/siem.db" ]; then
  echo ""
  echo -e "${YELLOW}🌱 Seeding database with demo data...${NC}"
  cd backend && node $SQLITE_FLAG src/utils/seed.js 2>&1 | grep -v ExperimentalWarning | grep -v "Use \`node"
  cd ..
  echo -e "${GREEN}✅ Database seeded${NC}"
else
  echo -e "${GREEN}✅ Database already exists (run 'npm run seed' in backend/ to reset)${NC}"
fi

echo ""
echo -e "${BOLD}🚀 Starting K3 SIEM...${NC}"
echo ""
echo -e "  ${BLUE}Backend API →${NC}  http://localhost:3001/api"
echo -e "  ${BLUE}WebSocket  →${NC}  ws://localhost:3001/ws"
echo -e "  ${BLUE}Frontend   →${NC}  http://localhost:3000"
echo ""
echo -e "  ${BOLD}Login:${NC} pbasnet / K3@2026"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop both servers${NC}"
echo ""

# Start backend in background
cd backend && node $SQLITE_FLAG src/index.js 2>&1 | grep -v ExperimentalWarning &
BACKEND_PID=$!
cd ..

# Wait for backend to be ready
sleep 2

# Start frontend (blocking)
cd frontend && npm start

# Cleanup on exit
kill $BACKEND_PID 2>/dev/null
echo -e "\n${YELLOW}K3 SIEM stopped.${NC}"
