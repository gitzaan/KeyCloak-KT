from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

app = Flask(__name__)

# Application Configuration
# These values are used if environment variables are not set
APP_CONFIG = {
    "KEYCLOAK_URL": "http://localhost:8080",
    "REALM_NAME": "siemens-login",
    "CLIENT_ID": "document-service",
    "CLIENT_SECRET": "29g9VLz1Ue3WuUQ8ybq6YlF4N1dbPNhm",
    "CORS_ORIGIN": "http://localhost:4200", 
    "FLASK_ENV": "development"
}

# Set up CORS
CORS(app, resources={r"/*": {"origins": os.environ.get('CORS_ORIGIN', APP_CONFIG["CORS_ORIGIN"])}}),

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get configuration values with fallback to our embedded defaults
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", APP_CONFIG["KEYCLOAK_URL"])
REALM_NAME = os.environ.get("REALM_NAME", APP_CONFIG["REALM_NAME"])
CLIENT_ID = os.environ.get("CLIENT_ID", APP_CONFIG["CLIENT_ID"])
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", APP_CONFIG["CLIENT_SECRET"])
AUTH_SERVER_URL = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect"

documents = [
    {"id": 1, "title": "General User Manual", "type": "general", "path": "/docs/user-manual.pdf"},
    {"id": 2, "title": "Technical Specifications", "type": "technical", "path": "/docs/specs.pdf"},
    {"id": 3, "title": "Operational Procedures", "type": "operational", "path": "/docs/procedures.pdf"},
    {"id": 4, "title": "System Architecture", "type": "admin", "path": "/docs/architecture.pdf"},
]

def get_token_info(token):
    logger.info("Validating token...")
    introspection_url = f"{AUTH_SERVER_URL}/token/introspect"
    payload = {
        'token': token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    try:
        response = requests.post(introspection_url, data=payload)
        if response.status_code == 200:
            logger.info("Token validation successful")
            return response.json()
        logger.error(f"Token validation failed: {response.status_code} - {response.text}")
        return None
    except Exception as e:
        logger.error(f"Exception during token validation: {str(e)}")
        return None

def check_resource_permission(token, resource_type, permission):
    logger.info(f"Checking permission: {resource_type}:{permission}")
    
    # Extract token info to check user roles directly if needed
    try:
        token_info = get_token_info(token)
        if not token_info:
            logger.error("Failed to get token info")
            return False
            
        realm_roles = token_info.get('realm_access', {}).get('roles', [])
        logger.info(f"User has realm roles: {realm_roles}")
        
        # Case-insensitive role check
        user_roles = [role.lower() for role in realm_roles]
        logger.info(f"Normalized user roles: {user_roles}")
        
        # Direct role-based permissions (simplifies debugging)
        # Allow any document access for administrators
        if "admin" in user_roles or "Admin" in realm_roles:
            logger.info("Admin access granted")
            return True
            
        # Allow technical docs for engineers
        if resource_type == "technical" and ("engineer" in user_roles or "Engineer" in realm_roles):
            logger.info("Engineer access to technical docs granted")
            return True
            
        # Allow operational docs for operators
        if resource_type == "operational" and ("operator" in user_roles or "Operator" in realm_roles):
            logger.info("Operator access to operational docs granted")
            return True
            
        # Allow general docs for all users (including default roles)
        if resource_type == "general" and ("user" in user_roles or "User" in realm_roles or 
                                          "default-roles-siemens-login" in realm_roles):
            logger.info("User access to general docs granted")
            return True
        
    except Exception as e:
        logger.error(f"Error in direct role check: {str(e)}")
    
    # If direct checks fail, try UMA ticket approach
    try:
        # Set proper audience from the token
        audience = token_info.get('azp', CLIENT_ID)
        logger.info(f"Using audience: {audience} for permission check")
        
        rpt_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
        payload = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
            'audience': audience,  # Use the audience from token
            'permission': f'{resource_type}:{permission}'
        }
        headers = {
            'Authorization': f'Bearer {token}'
        }
        
        response = requests.post(rpt_url, data=payload, headers=headers)
        logger.info(f"Permission check response status: {response.status_code}")
        
        if response.status_code != 200:
            logger.warning(f"Permission denied: {response.text}")
            
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Error checking permission: {str(e)}")
        return False

@app.route('/api/documents', methods=['GET'])
def list_documents():
    logger.info('Document list request received')
    
    # Get token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("No authorization token provided")
        return jsonify({"error": "No authorization token provided"}), 401
    
    token = auth_header.split(' ')[1]
    logger.info(f'Token received: {token[:20]}...')
    
    # Get token info for role-based filtering
    try:
        token_info = get_token_info(token)
        if token_info:
            logger.info(f"Token validation result: {token_info.get('active', False)}")
            if not token_info.get('active', False):
                logger.warning("Token is not active")
                return jsonify({"error": "Invalid or expired token"}), 401
        else:
            logger.error("Token info returned None")
            return jsonify({"error": "Token validation failed"}), 401
    except Exception as e:
        logger.error(f"Exception during token validation: {str(e)}")
        return jsonify({"error": "Token validation failed"}), 401
    
    logger.info("Token is valid, checking document permissions")
    user_info = token_info.get('preferred_username', 'unknown')
    logger.info(f"User: {user_info}")
    
    # Check and log realm roles if available
    if token_info.get('realm_access'):
        roles = token_info.get('realm_access', {}).get('roles', [])
        logger.info(f"User roles: {roles}")
    
    # Filter documents based on user's permissions
    user_documents = []
    for doc in documents:
        has_permission = check_resource_permission(token, doc['type'], 'view')
        logger.info(f"Permission check for {doc['type']}:view = {has_permission}")
        if has_permission:
            user_documents.append(doc)
    
    if not user_documents:
        logger.warning("No documents were authorized for this user")
        
    # TEMPORARY BYPASS: If no documents found, return all documents for debugging
    if not user_documents:
        logger.warning("FALLBACK: No documents authorized, returning general documents for debugging")
        # Only return general documents as fallback
        user_documents = [doc for doc in documents if doc['type'] == 'general']
    
    logger.info(f"Returning {len(user_documents)} documents")
    return jsonify(user_documents)

@app.route('/api/documents/<int:document_id>', methods=['GET'])
def get_document(document_id):
    doc = next((d for d in documents if d['id'] == document_id), None)
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "No authorization token provided"}), 401
    
    token = auth_header.split(' ')[1]
    
    has_permission = check_resource_permission(token, doc['type'], 'view')
    if not has_permission:
        logger.warning(f"Permission denied to view document {document_id}")
        return jsonify({"error": "You don't have permission to view this document"}), 403
    
    return jsonify(doc)

@app.route('/api/documents/<int:document_id>/download', methods=['POST'])
def download_document(document_id):
    doc = next((d for d in documents if d['id'] == document_id), None)
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "No authorization token provided"}), 401
    
    token = auth_header.split(' ')[1]
    
    has_permission = check_resource_permission(token, doc['type'], 'download')
    if not has_permission:
        logger.warning(f"Permission denied to download document {document_id}")
        return jsonify({"error": "You don't have permission to download this document"}), 403
    
    # In a real implementation, you'd generate a download link or stream the file
    download_url = f"http://localhost:5000/static{doc['path']}"
    return jsonify({"download_url": download_url})

@app.route('/api/documents', methods=['POST'])
def create_document():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "No authorization token provided"}), 401
    
    token = auth_header.split(' ')[1]
    
    # Check if user has permission to create documents
    has_permission = check_resource_permission(token, 'document', 'create')
    if not has_permission:
        logger.warning("Permission denied to create document")
        return jsonify({"error": "You don't have permission to create documents"}), 403
    
    new_doc = request.json
    if not new_doc:
        return jsonify({"error": "No document data provided"}), 400
        
    required_fields = ['title', 'type', 'path']
    for field in required_fields:
        if field not in new_doc:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    new_doc['id'] = max(d['id'] for d in documents) + 1
    documents.append(new_doc)
    
    logger.info(f"Document created: {new_doc['title']}")
    return jsonify(new_doc), 201

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "keycloak": KEYCLOAK_URL,
        "realm": REALM_NAME,
        "docs_count": len(documents)
    }), 200

@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({
        "status": "API is running",
        "keycloak_config": {
            "url": KEYCLOAK_URL,
            "realm": REALM_NAME,
            "client_id": CLIENT_ID,
            "client_secret_prefix": CLIENT_SECRET[:4] + "..."
        },
        "documents_count": len(documents)
    })

@app.route('/api/debug/documents', methods=['GET'])
def debug_documents():
    """Debug endpoint to check documents without permission checks"""
    logger.info("Debug endpoint accessed")
    return jsonify(documents)

@app.route('/api/debug/roles', methods=['GET'])
def debug_roles():
    """Debug endpoint to check roles from a token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "No authorization token provided"}), 401
    
    token = auth_header.split(' ')[1]
    token_info = get_token_info(token)
    
    if not token_info:
        return jsonify({"error": "Failed to get token info"}), 401
    
    return jsonify({
        "username": token_info.get('preferred_username', 'unknown'),
        "active": token_info.get('active', False),
        "realm_roles": token_info.get('realm_access', {}).get('roles', []),
        "resource_access": token_info.get('resource_access', {}),
        "audience": token_info.get('aud', []),
        "client_id": token_info.get('azp', 'unknown')
    })

if __name__ == '__main__':
    logger.info(f"Starting Flask API server on port 5000...")
    logger.info(f"Using Keycloak at {KEYCLOAK_URL}, realm {REALM_NAME}")
    app.run(host='0.0.0.0', debug=True, port=5000)