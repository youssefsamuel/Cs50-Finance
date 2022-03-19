import os
import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    try:
        os.environ["API_KEY"] = [pk_51f295b0ef9f480aa7c6160d089103d7]
    except:
        raise RuntimeError("API_KEY not set")



@app.route("/")
@login_required
def index():
    userid = session["user_id"]
    rows = db.execute("SELECT symbol, name, shares, price, money FROM purchases WHERE user_id = ?", userid)
    userid = session["user_id"]
    usercash = db.execute("SELECT cash FROM users WHERE id=?", userid)
    usermoney = usercash[0]["cash"]
    totalmoney = usermoney
    for row in rows:
        totalmoney += row['money']
    return render_template("index.html", rows=rows, usermoney=usermoney, totalmoney=totalmoney)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")
    else:
        shares = int(request.form.get("shares"))
        symbol = request.form.get("symbol")
        if shares <= 0:
            return apology("You must provide a positive integer")
        if symbol == "":
            return apology("You must provide a symbol")
        result = lookup(symbol)
        if result == None:
            return apology("Invalid symbol")
        name = result["name"]
        price = float(result["price"])
        money_paid = price * shares
        stock_symbol = result["symbol"]
        userid = session["user_id"]
        usercash = db.execute("SELECT cash FROM users WHERE id=?", userid)
        usermoney = usercash[0]["cash"]
        if money_paid > usermoney:
            return apology("You can not afford this stock")
        time = datetime.datetime.now()

        new_cash = usermoney - money_paid

        db.execute("UPDATE users SET cash = ? WHERE id=?",new_cash, userid)

        symbols = db.execute("SELECT symbol FROM purchases WHERE user_id = ?", userid)

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)", userid, symbol, shares, price, time)
        found = 0
        for row in symbols:
            if stock_symbol == row['symbol']:
                found = 1
        if found == 1:
            shares_owned = db.execute("SELECT shares FROM purchases WHERE user_id=? AND symbol=? ", userid, stock_symbol)
            shares_owned = shares_owned[0]['shares']
            shares_now = shares_owned + shares
            money_now = price * shares_now
            db.execute("UPDATE purchases SET shares=?, money=? WHERE user_id = ? AND symbol = ?", shares_now, money_now, userid, stock_symbol)

        else:
            db.execute("INSERT INTO purchases (user_id, symbol, name, price, shares, money, time) VALUES (?, ?, ?, ?, ?, ?, ?)",userid, stock_symbol, name, price, shares, money_paid, time)

        return redirect("/")


@app.route("/history")
@login_required
def history():
    userid = session["user_id"]
    rows = db.execute("SELECT symbol, shares, price, transacted FROM transactions WHERE user_id = ?", userid)
    return render_template("history.html", rows = rows  )


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")

    else:
        symbol = request.form.get("symbol")
        if symbol == "":
            return apology("You must provide a symbol")
        result = lookup(symbol)
        if result == None:
            return apology("Invalid symbol")
        else:
            return render_template("quoted.html", result=result)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    else:
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        elif not request.form.get("password_confirmation"):
            return apology("must provide password", 403)

        password = request.form.get("password")
        password_confirmation = request.form.get("password_confirmation")

        if password != password_confirmation:
            return apology("Passwords do not match", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",username=request.form.get("username"))

        if len(rows) != 0:
             return apology("Username already exists", 403)

        username = request.form.get("username")
        hashed_password = generate_password_hash(password, method='pbkdf2:sha512')

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashed_password)", username=username, hashed_password=hashed_password)

        return redirect("/")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        userid = session["user_id"]
        rows = db.execute("SELECT symbol FROM purchases WHERE user_id=?", userid)
        return render_template("sell.html", rows=rows)
    else:
        userid = session["user_id"]
        stock = request.form.get("symbol")
        if stock == "Symbol":
            return apology("You must choose a stock")
        shares_to_sell = int(request.form.get("shares"))
        if shares_to_sell == 0:
            return apology("You can not sell 0 idiot")
        if shares_to_sell < 0:
            return apology("Less than 0? Sure?")
        shares_owned = db.execute("SELECT shares FROM purchases WHERE user_id = ? AND symbol = ?", userid, stock)
        shares_owned = int(shares_owned[0]['shares'])
        if shares_to_sell > shares_owned:
            return apology("You do not have all this")
        shares_owned = shares_owned - shares_to_sell
        result = lookup(stock)
        price = float(result["price"])
        money_now = price * shares_owned
        usercash = db.execute("SELECT cash FROM users WHERE id=?", userid)
        usermoney = usercash[0]["cash"]
        money_gained = price * shares_to_sell
        new_cash = usermoney + money_gained
        time = datetime.datetime.now()
        shares_to_sell = shares_to_sell * -1

        db.execute("UPDATE users SET cash = ? WHERE id=?",new_cash, userid)
        db.execute("UPDATE purchases SET shares = ?, money = ? WHERE user_id = ? AND symbol = ?", shares_owned, money_now, userid, stock)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)", userid, stock, shares_to_sell, price, time)

        return redirect("/")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "GET":
        return render_template("change.html")
    else:
        old = request.form.get("old")
        new = request.form.get("new")
        conf = request.form.get("confirm")

        if not old:
            return apology("must provide old pass", 403)
        if not new:
            return apology("must provide new pass", 403)
        if not conf:
            return apology("must confirm new pass", 403)

        if new != conf:
            return apology("pass dnt match", 403)

        user = session["user_id"]

        rows = db.execute("SELECT hash FROM users WHERE id = ?", user)

        if not check_password_hash(rows[0]["hash"], old):
            return apology("invalid password", 403)

        hashed = generate_password_hash(new, method='pbkdf2:sha512')
        db.execute("Update users SET hash = ?", hashed)

        return redirect("/")



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
