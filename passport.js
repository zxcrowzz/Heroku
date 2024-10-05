const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/User');
const bcrypt = require('bcrypt');

function initialize(passport) {
    const authenticateUser = async (email, password, done) => {
    console.log("Attempting to authenticate user:", email);
    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.error("No user found with that email");
            return done(null, false, { message: 'No user with that email' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.error("Password incorrect for user:", email);
            return done(null, false, { message: 'Password incorrect' });
        }

        if (!user.isConfirmed) {
            console.error("Email not confirmed for user:", email);
            return done(null, false, { message: 'Email not confirmed' });
        }

        return done(null, user);
    } catch (error) {
        console.error("Authentication error:", error);
        return done(error);
    }
};

    };

    // Use the local strategy for authentication
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));

    // Serialize the user to store in the session
    passport.serializeUser((user, done) => {
        console.log("Serializing user:", user); // Debugging log
        done(null, user._id); // Use user._id for MongoDB
    });

    // Deserialize the user from the session
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            if (!user) {
                return done(new Error('User not found'), null);
            }
            console.log("Deserialized user:", user); // Debugging log
            done(null, user);
        } catch (error) {
            console.error("Deserialization error:", error);
            done(error, null);
        }
    });
}

module.exports = initialize;
