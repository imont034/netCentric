import os, json
from flask import Flask

html = '''
<html>
    <head>
        <title>Test</title>
    </head>
    <body>
        <div>
            <p>ABC</p>
        </div>
    </body>
</html>
       '''
@app.route('/')
def home():
    return html

if __name__ == '__main__':
    app.run()