import passport from 'passport'

let _passport: passport.PassportStatic

export default function configurePassport() {
  if (!_passport) {
    _passport = passport
  }

  return _passport
}
