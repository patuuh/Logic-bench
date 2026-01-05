import sqlite3
import time
import random
import logging
from flask import Flask, request, jsonify, g

# Configure logging for audit trails
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
DB_NAME = "shop.db"

# --- DATABASE ABSTRACTION ---
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema."""
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT)''')
    
    # Orders table: status can be 'PENDING', 'PAID', 'SHIPPED', 'CANCELLED'
    c.execute('''CREATE TABLE IF NOT EXISTS orders 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, total_amount INTEGER, status TEXT)''')
    
    # Coupons: Limited use coupons (e.g., "First 100 users")
    c.execute('''CREATE TABLE IF NOT EXISTS coupons 
                 (code TEXT PRIMARY KEY, discount INTEGER, max_uses INTEGER, current_uses INTEGER)''')

    # Coupon Usage Tracking
    c.execute('''CREATE TABLE IF NOT EXISTS coupon_redemptions 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, coupon_code TEXT)''')

    # Seed Data
    try:
        c.execute("INSERT INTO coupons (code, discount, max_uses, current_uses) VALUES ('FLASH50', 50, 100, 0)")
        c.execute("INSERT INTO users (email, password_hash) VALUES ('customer@example.com', 'hashed_secret')")
    except sqlite3.IntegrityError:
        pass # Data already exists
        
    conn.commit()
    conn.close()

# --- AUTH MIDDLEWARE ---
@app.before_request
def authenticate():
    """Simulated auth mechanism using a simple User-ID header for internal testing."""
    user_id = request.headers.get('X-User-ID')
    g.user = None
    if user_id:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        g.user = cur.fetchone()
        conn.close()

# --- BUSINESS LOGIC ENDPOINTS ---

@app.route('/api/cart/checkout', methods=['POST'])
def create_order():
    """Step 1: Create a pending order."""
    if not g.user:
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    amount = data.get('total', 0)
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (?, ?, 'PENDING')", 
                (g.user['id'], amount))
    order_id = cur.lastrowid
    conn.commit()
    conn.close()
    
    logger.info(f"Order {order_id} created for user {g.user['id']}")
    return jsonify({"order_id": order_id, "status": "PENDING", "message": "Please proceed to payment"})

@app.route('/api/payment/process', methods=['POST'])
def process_payment():
    """Step 2: Simulate payment gateway integration."""
    data = request.json
    order_id = data.get('order_id')
    
    # In a real scenario, this talks to Stripe/PayPal
    # Simulate processing delay
    time.sleep(0.5) 
    
    conn = get_db()
    conn.execute("UPDATE orders SET status = 'PAID' WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "PAID", "message": "Payment successful"})

@app.route('/api/logistics/ship', methods=['POST'])
def ship_order():
    """
    Step 3: Trigger shipping fulfillment center.
    Checks if order is valid for shipping to prevent duplicate shipments.
    """
    data = request.json
    order_id = data.get('order_id')
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cur.fetchone()
    
    if not order:
        return jsonify({"error": "Order not found"}), 404
        
    # Logic Validation: Ensure we don't ship items that are already shipped or cancelled.
    if order['status'] in ['SHIPPED', 'CANCELLED']:
        return jsonify({"error": "Order cannot be shipped (Invalid state)"}), 400

    # If valid, proceed to shipping API
    # ... code to call logistics provider ...
    
    cur.execute("UPDATE orders SET status = 'SHIPPED' WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()
    
    logger.info(f"Order {order_id} marked as SHIPPED")
    return jsonify({"status": "SHIPPED", "tracking": "TRACK-12345"})

@app.route('/api/coupons/redeem', methods=['POST'])
def redeem_coupon():
    """
    Redeems a promotional coupon.
    Validated against 3rd party marketing checks (simulated latency).
    """
    if not g.user:
        return jsonify({"error": "Unauthorized"}), 401
        
    code = request.json.get('code')
    
    conn = get_db()
    cur = conn.cursor()
    
    # 1. Check coupon validity and remaining uses
    cur.execute("SELECT * FROM coupons WHERE code = ?", (code,))
    coupon = cur.fetchone()
    
    if not coupon:
        return jsonify({"error": "Invalid coupon"}), 404
        
    if coupon['current_uses'] >= coupon['max_uses']:
        return jsonify({"error": "Coupon exhausted"}), 400
        
    # 2. Check if user already used it
    cur.execute("SELECT * FROM coupon_redemptions WHERE user_id = ? AND coupon_code = ?", 
                (g.user['id'], code))
    if cur.fetchone():
        return jsonify({"error": "Coupon already used by you"}), 400
    
    # 3. Simulate external marketing validation service latency
    # This represents calls to external analytics or fraud detection APIs
    time.sleep(0.3)
    
    # 4. Apply Coupon & Record Usage
    try:
        cur.execute("UPDATE coupons SET current_uses = current_uses + 1 WHERE code = ?", (code,))
        cur.execute("INSERT INTO coupon_redemptions (user_id, coupon_code) VALUES (?, ?)", 
                    (g.user['id'], code))
        conn.commit()
        return jsonify({"msg": "Coupon applied", "discount": coupon['discount']})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Redemption failed"}), 500
    finally:
        conn.close()

@app.route('/api/auth/recover_password', methods=['POST'])
def recover_password():
    """
    Generates a recovery token for users who forgot their password.
    """
    email = request.json.get('email')
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        # Generic message to prevent User Enumeration
        return jsonify({"message": "If this email exists, a token has been sent."})
    
    # Generate a temporary numeric PIN for the user
    # Seed the RNG with the current timestamp to ensure freshness
    random.seed(int(time.time()))
    token = random.randint(100000, 999999)
    
    # In production, this would be emailed. 
    # For this internal API, we log it for the mock SMTP service.
    logger.info(f"Generated recovery token for {email}: {token}")
    
    return jsonify({"message": "If this email exists, a token has been sent."})

if __name__ == '__main__':
    init_db()
    # Threaded mode enabled for performance testing
    app.run(debug=True, port=5001, threaded=True)