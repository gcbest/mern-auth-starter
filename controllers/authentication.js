const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
    // standards of JWTs
    // sub stands for subject (who is this token about)
    // iat stands for issued at time
    const timestamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = (req, res, next) => {
    // user has already had their email and password auth'd
    // we just need to give them a token

    // in the done() callback from localLogin, passport adds the returned user to req.user
    res.send({ token: tokenForUser(req.user) });
};

exports.signup = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;

    if (!email || !password) return res.status(422).send({ error: 'You must provide email & password' });

    // see if user with given email exists
    User.findOne({ email }, (err, existingUser) => {
       if (err) { return next(err) }

        // if email does exist, return an error
        if (existingUser) {
           return res.status(422).send({ error: 'Email already exists' });
       }

        // if email doesn't exist, create new user record
        const user = new User({
            email,
            password
        });

       user.save((err) => {
          if (err) { return next(err) };
       });

        // respond to request indicating user was created
        res.json({ token: tokenForUser(user) });

    });
};