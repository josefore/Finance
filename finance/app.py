import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
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
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    # Variables
    owns = db.execute("SELECT cmp_id, quantity FROM belongings WHERE user_id = ?;", session["user_id"])
    if owns != None:
        stock = []
        balance = session["cash"]
        for share in owns:
            symbol = db.execute("SELECT symbol FROM companies WHERE id = ?", share["cmp_id"])
            if symbol == []:
                return apology("Company not found", 401)
            share_symbol = symbol[0]["symbol"]
            share_info = lookup(share_symbol)
            if share_info == None:
                return apology("Share not found", 401)
            share["symbol"] = share_symbol
            share["name"] = share_info["name"]
            share["price"] = usd(share_info["price"])

            # Check if it has been up or down
            share["u_o_d"] = 0
            share["pctg"] = ""
            pctg = 0
            consult = db.execute(
                "SELECT pPrice FROM transactions WHERE type = ? AND owner = ? AND company IN (SELECT id FROM companies WHERE symbol = ?) ORDER BY date LIMIT 1;", "P", session["user_id"], share_symbol)
            if consult == None:
                return apology("Consult error", 704)
            former_price = consult[0]["pPrice"]
            if former_price < share_info["price"]:
                share["u_o_d"] = 2
                pctg = (share_info["price"] - former_price) * 100 / former_price
                share["pctg"] = "{:.2f}".format(pctg)
            if former_price > share_info["price"]:
                share["u_o_d"] = 1
                pctg = (former_price - share_info["price"]) * 100 / former_price
                share["pctg"] = "{:.2f}".format(pctg)

            total = share_info["price"] * share["quantity"]
            share["g_l"] = usd(pctg / 100 * total)
            share["total"] = usd(total)
            balance += share_info["price"] * share["quantity"]
            stock.append(share)

        session["stock"] = stock
        session["balance"] = balance
        return render_template("index.html", cash=usd(session["cash"]), stock=stock, balance=usd(balance))
    return apology("Not found", 401)


@app.route("/buy", methods=["POST", "GET"])
@login_required
def buy():
    if request.method == "POST":
        sn = request.form.get("shares")
        shares_number = 0
        if not sn.isnumeric():
            return apology("Invalid input", 400)
        shares_number = int(sn)
        symbol = request.form.get("symbol")
        p = lookup(symbol)
        if p == None:
            return apology("Share not found", 400)
        price = p["price"]
        balance = session["cash"] - shares_number * price
        print(balance)
        if shares_number > 0 and balance >= 0:
            # Update current balance
            db.execute("UPDATE users SET cash = ? WHERE id = ?;", balance, session["user_id"])
            session["cash"] = balance
            arr = db.execute("SELECT id FROM companies WHERE symbol = ?;", symbol)
            if arr == []:
                db.execute("INSERT INTO companies (symbol) VALUES (?);", symbol)
            ext_id = db.execute("SELECT id FROM companies WHERE symbol = ?;", symbol)
            cmp_id = ext_id[0]["id"]
            db.execute("INSERT INTO transactions (company, owner, pPrice, amount, type) VALUES (?, ?, ?, ?, ?);",
                       cmp_id, session["user_id"], price, shares_number, "P")
            tgt = db.execute("SELECT quantity FROM belongings WHERE user_id = ? AND cmp_id = ?;", session["user_id"], cmp_id)
            if tgt == []:
                db.execute("INSERT INTO belongings VALUES (?, ?, ?);", session["user_id"], cmp_id, shares_number)
                return redirect("/")
            acquisitions = tgt[0]["quantity"]
            db.execute("UPDATE belongings SET quantity = ? WHERE user_id = ? AND cmp_id = ?;",
                       (acquisitions + shares_number), session["user_id"], cmp_id)
            return redirect("/")
        return apology("Request error", 400)

    if request.method == "GET":
        return render_template("buy.html", cash=usd(session["cash"]), balance=usd(session["balance"]))

    return apology("Not enough funds", 400)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    trs_oc = []
    transactions = db.execute(
        "SELECT companies.symbol, transactions.amount, transactions.pPrice, transactions.type, transactions.date FROM transactions INNER JOIN companies ON transactions.company=companies.id WHERE transactions.owner = ? ORDER BY date DESC;", session["user_id"])
    if transactions == []:
        return apology("No transactions found", 401)
    for trsct in transactions:
        data = lookup(trsct["symbol"])
        if data == None:
            return apology("Transaction not found", 401)
        trsct["name"] = data["name"]
        if trsct["type"] == "P":
            trsct["type"] = "Purchased"
        else:
            trsct["type"] = "Sold"
        trs_oc.append(trsct)
    return render_template("history.html", transactions=trs_oc)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?;", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["cash"] = rows[0]["cash"]

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
    if request.method == "POST":
        if request.form.get("symbol"):
            symbol = lookup(request.form.get("symbol"))
            if symbol != None:
                session["last_symbol"] = symbol["symbol"]
                symbol["price"] = usd(symbol["price"])
                return render_template("quoted.html", results=symbol, cash="{:.2f}".format(session["cash"]))

    if request.method == "GET":
        return render_template("quote.html")

    return apology("Symbol not found", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must sign in username", 400)

        if not request.form.get("password"):
            return apology("must set a password", 400)

        username = request.form.get("username")
        pwHash = generate_password_hash(request.form.get("password"))
        usernames = db.execute("SELECT username FROM users;")
        users = []
        for e in usernames:
            users.append(e["username"])
        # Check username doesn't exist
        if username in users:
            print(True)
            return apology("the username already exists", 400)
        else:
            # Check if confirm password is correct
            if check_password_hash(pwHash, request.form.get("confirmation")):
                db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", username, pwHash)
                return redirect("/login")
            return apology("password confirmation does not match", 400)

    return apology("Could not be registered", 400)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("sell.html", stocks=session["stock"], cash=usd(session["cash"]), balance=usd(session["balance"]))
    if request.method == "POST":
        profit = 0
        owned = 0
        """if not request.form.get(shares["symbol"]):
        return apology("Not found", 400)"""
        if request.form.get("symbol") and request.form.get("shares"):
            symbol = request.form.get("symbol")
            shares = int(request.form.get("shares"))
            symbols = []
            for s in session["stock"]:
                if s["symbol"] == symbol:
                    owned = s["quantity"]
            if shares > owned or shares < 1:
                return apology("Not enough shares", 400)
            crt_price = lookup(symbol)
            if crt_price == None:
                return apology("Share not found", 400)
            price = crt_price["price"]
            profit += shares * price
            name = crt_price["name"]
            if shares == owned:
                db.execute(
                    "DELETE FROM belongings WHERE user_id = ? AND cmp_id IN (SELECT id FROM companies WHERE symbol = ?);", session["user_id"], symbol)
                st = []
                for s in session["stock"]:
                    if s["symbol"] != symbol:
                        st.append(s)
                session["stock"] = st
            else:
                db.execute("UPDATE belongings SET quantity = ? WHERE user_id = ? AND cmp_id IN (SELECT id FROM companies WHERE symbol = ?);",
                           (owned - shares), session["user_id"], symbol)
                for s in session["stock"]:
                    if s["symbol"] == symbol:
                        s["quantity"] -= shares
            db.execute("INSERT INTO transactions (owner, company, pPrice, amount, type) VALUES (?, (SELECT id FROM companies WHERE symbol = ?), ?, ?, ?)",
                       session["user_id"], symbol, price, shares, "S")
            session["cash"] += profit
            db.execute("UPDATE users SET cash = ? WHERE id = ?", session["cash"], session["user_id"],)
            return redirect("/")
        return apology("Empty form fields", 400)
    return apology("Page not found", 400)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
