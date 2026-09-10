def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # SECURE: Ensure full authenticated identity exists AND 2FA is satisfied
        if "user_id" not in session or not session.get("is_fully_authenticated", False):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    user = authenticate_user(username, password)
    if not user:
        return "Invalid credentials", 401

    if user["two_factor_enabled"]:
        # SECURE: Store only a temporary pre-auth state, NOT a fully authenticated session
        session["pre_auth_user_id"] = user["id"]
        session["is_fully_authenticated"] = False
        return redirect(url_for("two_factor"))

    # For accounts without 2FA, grant full session
    session["user_id"] = user["id"]
    session["is_fully_authenticated"] = True
    return redirect(url_for("dashboard"))


@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    # Only allow access if user passed Step 1 (pre-auth stage)
    if "pre_auth_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code")
        user_id = session["pre_auth_user_id"]
        
        if verify_totp(user_id, code):
            # SECURE: Promote pre-auth to fully authenticated state
            session["user_id"] = user_id
            session["is_fully_authenticated"] = True
            session.pop("pre_auth_user_id", None)
            return redirect(url_for("dashboard"))
            
        return "Invalid 2FA Code", 400

    return render_template("2fa.html")
