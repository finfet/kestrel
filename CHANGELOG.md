# Changelog

## Version 1.0.0-rc1

**Date**: 2023-12-05

**Changes**

- Unreleased

## Version 0.11.0

**Date**: 2023-09-25

**Changes**

- Added the abilility to input and output data using unix pipes.
- Changed the format of private keys. The private key format's salt value has
  been increase from 16 to 32 bytes in order to give encrypted private keys
  the same security properties as password encrypted files.
- Changed the file format of key encrypted files. The noise handshake hash
  is now bound to the payload key for improved security.

**Note**:

**THIS IS A BREAKING RELEASE**

All files that were encrypted with versions prior to this will no longer
decrypt. You must decrypt any files with the previous version and then
re-encrypt them with the new version. All private keys must also be
regenerated.

No changes to the file formats are expected after the 1.0.0 release.

## Version 0.10.1

- Fixed crash when running kestrel key
- Improved cli error message output

## Version 0.10.0

- Warn on use of empty password

## Version 0.9.0

- Initial Release
