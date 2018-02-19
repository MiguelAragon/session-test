let express = require('express'),
	path = require('path'),
	passport = require('passport'),
	cookieParser = require('cookie-parser'),
	session = require('express-session'),
	bodyParser = require('body-parser'),
	LocalStrategy = require('passport-local').Strategy;

let app = express();


// BodyParser Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());


// Express Session
app.use(session({
    secret: 'SUBFUWOUBEFOUBE)"F/(&F#(/)',
    saveUninitialized: true,
    resave: true,
    cookie: {httpOnly: false,  maxAge:  10 * 1000}, //time in miliseconds
}));


// Passport init
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  function(username, password, done) {
  	let user = {username: "Mike", password: "123"};
  	if (!user) return done(null, false, { message: 'Incorrect username.' });
    if(user.password != '123') return done(null, false, { message: 'Incorrect password.' });
  	return done(null, user);
  }
));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.post('/login', passport.authenticate('local', {successRedirect: '/logged', failureRedirect: '/login'}), function(req, res){
	res.redirect('/');
});

app.get('/logged', ensureAuthenticated, function(req, res){
	res.json(req.user);
});

app.get('/user', ensureAuthenticated, function(req, res){
	res.json(req.user);
});

function ensureAuthenticated(req, res, next){
	if(req.isAuthenticated()){
		return next();
	} else {
		//req.flash('error_msg','You are not logged in');
		res.redirect('/login');
	}
}

app.listen(3000, function(){
	console.log("Server running on port 3000");
});

