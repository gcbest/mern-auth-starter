const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs');
const Schema = mongoose.Schema;

// Define our model
const userSchema = new Schema({
    email: { type: String, unique: true, lowercase: true },
    password: String
});

// On Save Hook, encrypt password
// Before saving a model, run this function
userSchema.pre('save', function(next) {
   // get access to the specific user model
   const user = this;

   // generate a salt then run callback
   bcrypt.genSalt(10, (err, salt) => {
       if (err) return next(err);

       // encrypt the password using the salt
       bcrypt.hash(user.password, salt, null, (err, hash) => {
           if (err) return next(err);

           // overwrite password with the encrypted password
           user.password = hash;
           // save the model
           next();
       })
    });
});


userSchema.methods.comparePasswords = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
        if (err) return callback(err);

        callback(null, isMatch);
    })
};

// Create model class
const User = mongoose.model('user', userSchema);

// Export model
module.exports = User;