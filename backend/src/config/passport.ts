import { PassportStatic } from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { User, IUser } from '../models/User'; // Assuming User model exists
import { logger } from '../../utils/logger';

export const setupPassport = (passport: PassportStatic) => {
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await User.findOne({ username });

        if (!user) {
          return done(null, false, { message: 'Incorrect username.' });
        }

        const isMatch = await user.comparePassword(password);

        if (!isMatch) {
          return done(null, false, { message: 'Incorrect password.' });
        }

        logger.info(`User ${username} successfully authenticated.`);
        return done(null, user);
      } catch (err: any) {
        logger.error(`Passport authentication error for user ${username}: ${err.message}`);
        return done(err);
      }
    })
  );

  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err: any) {
      logger.error(`Passport deserialization error for user ID ${id}: ${err.message}`);
      done(err);
    }
  });
};