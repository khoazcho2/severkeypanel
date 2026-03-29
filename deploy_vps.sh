#!/bin/bash
# Deploy to VPS 103.249.201.186

VPS_USER="root"  # Thay username VPS
VPS_IP="103.249.201.186"
APP_DIR="/root/key-server"  # Thư mục trên VPS

echo "=== Deploy Key Server to VPS ==="

# Tạo thư mục
ssh $VPS_USER@$VPS_IP "mkdir -p $APP_DIR"

# Copy files
scp server.py admin.html serverkey.db run_server.sh $VPS_USER@$VPS_IP:$APP_DIR/

# Tạo run_server.sh trên VPS
ssh $VPS_USER@$VPS_IP "cat > $APP_DIR/run_server.sh << 'EOF'
#!/bin/bash
cd \$(dirname \$0)
python3 server.py
EOF"

ssh $VPS_USER@$VPS_IP "chmod +x $APP_DIR/run_server.sh"

# Kill old process
ssh $VPS_USER@$VPS_IP "pkill -f 'python.*server.py' || true"

# Start background
ssh $VPS_USER@$VPS_IP "nohup $APP_DIR/run_server.sh > $APP_DIR/server.log 2>&1 &"

echo "✅ Deployed! Check: http://$VPS_IP:5000/admin.html"
echo "Log: ssh $VPS_USER@$VPS_IP 'tail -f $APP_DIR/server.log'"
echo "Status: ssh $VPS_USER@$VPS_IP 'ps aux | grep server.py'"
