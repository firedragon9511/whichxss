from flask import Flask, request, abort

app = Flask(__name__)

waf = [
    "onload=",
    "onerror=",
    "onclick=",
    "ondrag=",
    "<script",
    "onsubmit",
    "<img",
    "<iframe",
    "javascript:",
    "alert("
]

@app.route('/')
def home():
    search = request.args.get('search')
    for w in waf:
        if w in search:
            return search, 403

    return 'Search: {}'.format(search)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
