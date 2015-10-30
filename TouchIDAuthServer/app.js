var express = require('express');
var uuid = require('node-uuid');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');

var app = express();

app.use(bodyParser.json());

app.get('/', function (req, res) {
  res.send('TouchID authentication server example');
});

app.post('/pubkey', function (req, res) {
	console.log("Registering a public key for user: " + req.body["user"]);
	var buf = new Buffer(req.body["key"], 'base64');
	console.log(buf.toString());
	res.status(200).send({"user": {"id": uuid.v4()}});
});

app.post('/login', function (req, res) {
	var token = req.body["jwt"];
	console.log("Login with JWT: " + token);
	var payload = jwt.decode(token);
	console.log("Received payload " + JSON.stringify(payload));
	res.status(200).end();
});

var server = app.listen(3000, function () {

  var host = server.address().address;
  var port = server.address().port;

  console.log('Example app listening at http://%s:%s', host, port);

});