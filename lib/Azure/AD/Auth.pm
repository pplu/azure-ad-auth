package Azure::AD::Auth;
  our $VERSION = '0.04';
1;
### main pod documentation begin ###

=encoding UTF-8

=head1 NAME

Azure::AD::Auth - Libraries for authenticating through Azure AD

=head1 DESCRIPTION

This set of modules helps you authenticate with Azure Active Directory. Note that
"Azure Active Directory" is not "Active Directory". Azure Active Directory is an
online authentication service that speaks OAuth2, SAML and other protocols (and 
doesn't speak LDAP, like traditional Active Directory"

This distribution is split into specialized modules for each type of authentication
flow:

=head1 AUTHENTICATION FLOWS

L<Azure::AD::ClientCredentials>

L<Azure::AD::ClientCredentialsV2>

L<Azure::AD::DeviceLogin>

L<Azure::AD::Password>

=head1 SEE ALSO

L<https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc>

=head1 AUTHOR

    Jose Luis Martinez
    pplusdomain@gmail.com

=head1 THANKS

iamlgh for Client Credentials V2 module

=head1 BUGS and SOURCE

The source code is located here: L<https://github.com/pplu/azure-ad-auth>

Please report bugs to: L<https://github.com/pplu/azure-ad-auth/issues>

=head1 COPYRIGHT and LICENSE

Copyright (c) 2020 by Jose Luis Martinez

This code is distributed under the Apache 2 License. The full text of the 
license can be found in the LICENSE file included with this module.

=cut
