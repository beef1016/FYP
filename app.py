from flask import Flask, render_template, request, flash
import ipaddress

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Needed for flashing messages

@app.route('/', methods=['GET', 'POST'])
def index():
    validation_message = None
    message_category = None

    if request.method == 'POST':
        target = request.form.get('target')
        
        # This is the "Early Implementation" logic: Validating the IP
        try:
            # Check if it's a valid IPv4 address
            ipaddress.ip_address(target)
            validation_message = f"Success: Target {target} is valid. Engine is ready to scan."
            message_category = "success"
        except ValueError:
            # If not an IP, check if it is a generic domain (simple check)
            if '.' in target and len(target) > 3:
                validation_message = f"Success: Target {target} resolved as a Domain."
                message_category = "success"
            else:
                validation_message = f"Error: '{target}' is not a valid IP or Domain."
                message_category = "error"

    return render_template('index.html', message=validation_message, category=message_category)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
