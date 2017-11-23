const Authentication = require('./controllers/authentication');
require('./services/passport'); // We just want to make sure the contents of that file get processed so its functions/variables are available.
const passport = require('passport');

// passport wants to make a cookie based session but since we are using tokens we want to prevent that
const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });

module.exports = (app) => {
    app.get('/', requireAuth, (req, res) => {
       res.send({ hi: 'there' });
    });

    app.post('/signin', requireSignin, Authentication.signin);
    app.post('/signup', Authentication.signup);
};