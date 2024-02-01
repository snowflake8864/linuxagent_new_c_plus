/*
  Copyright (c) 2005-2009 by Jakob Schroeter <js@camaya.net>
  This file is part of the gloox library. http://camaya.net/gloox

  This software is distributed under a license. The full license
  agreement can be found in the file LICENSE in this distribution.
  This software may not be copied, modified, sold or distributed
  other than expressed in the named license agreement.

  This software is distributed without any warranty.
*/


#ifndef BASE64_H__
#define BASE64_H__

namespace ASBase64Util
{
	std::string Base64Encode( const std::string& input);
	std::string Base64Encode(const unsigned char* input, unsigned int nInputlen);
	std::string Base64Decode( const std::string& input);
	unsigned char* Base64Decode(const std::string& input, unsigned int& nContLen);
};

#endif // BASE64_H__
