const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local strategy
const localOptions = { usernameField: 'email' }; // look at the email property for the username
const localLogin = new LocalStrategy(localOptions, (email, password, done) => {
    // verify this email and password, call done with the user if it is the correct email and password
    // otherwise call done with false
    User.findOne({ email: email }, (err, user) => {
        if (err) return done(err);
        if(!user) return done(null, false);  // user not found

        // compare passwords but we never decrypt our saved password, use bcrypt to compare hashed passwords
        user.comparePasswords(password, (err, isMatch) => {
            if (err) return done(err);

            if (!isMatch) return done(null, false);

            return done(null, user);
        });

    });
});


// Setup options for Jwt Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'), // have to tell the strategy where to look for this request
    secretOrKey: config.secret
};

// Create Jwt Strategy
// the payload is the token property we created earlier with the 'sub' and 'iat' properties
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
    // see if the user ID in the payload exists in our DB
    // if it does call done with that object, otherwise call done without a user object
    User.findById(payload.sub, (err, user) => {
        // whoever gave us this token wasn't authenticated
        if (err) return done(err, false);

        if (user) {
            done(null, user);
        } else {
            // couldn't find the user
            done(null, false)
        }

    })
});


// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);