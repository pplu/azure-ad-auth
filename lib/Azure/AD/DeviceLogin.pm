package Azure::AD::DeviceLogin;
  use Moo;
  use Azure::AD::Errors;
  use Types::Standard qw/Str Int InstanceOf CodeRef/;
  use JSON::MaybeXS;
  use HTTP::Tiny;

  our $VERSION = '0.01';

  has ua_agent => (is => 'ro', isa => Str, default => sub {
    'Azure::AD::DeviceLogin ' . $Azure::AD::DeviceLogin::VERSION
  });

  has ua => (is => 'rw', required => 1, lazy => 1,
    default     => sub {
      my $self = shift;
      HTTP::Tiny->new(
        agent => $self->ua_agent,
        timeout => 60,
      );
    }
  );

  has resource_id => (
    is => 'ro',
    isa => Str,
    required => 1,
  );

  has message_handler => (
    is => 'ro',
    isa => CodeRef,
    required => 1,
  );

  has tenant_id => (
    is => 'ro',
    isa => Str,
    required => 1,
    default => sub {
      $ENV{AZURE_TENANT_ID}
    }
  );

  has client_id => (
    is => 'ro',
    isa => Str,
    required => 1,
    default => sub {
      $ENV{AZURE_CLIENT_ID}
    }
  );

  has ad_url => (
    is => 'ro',
    isa => Str,
    default => sub {
      'https://login.microsoftonline.com'
    },
  );

  has device_endpoint => (
    is => 'ro',
    isa => Str,
    lazy => 1,
    default => sub {
      my $self = shift;
      sprintf '%s/%s/oauth2/devicecode', $self->ad_url, $self->tenant_id;
    }
  );

  has token_endpoint => (
    is => 'ro',
    isa => Str,
    lazy => 1,
    default => sub {
      my $self = shift;
      sprintf "%s/%s/oauth2/token", $self->ad_url, $self->tenant_id;
    }
  );

  sub access_token {
    my $self = shift;
    $self->_refresh;
    $self->current_creds->{ access_token };
  }

  has current_creds => (is => 'rw');

  has expiration => (
    is => 'rw',
    isa => Int,
    lazy => 1,
    default => sub { 0 }
  );

  sub _refresh_from_cache {
    my $self = shift;
    #TODO: implement caching strategy
    return undef;
  }

  sub _save_to_cache {
    my $self = shift;
    #TODO: implement caching strategy
  }

  sub get_device_payload {
    my $self = shift;
    my $device_response = $self->ua->post_form(
      $self->device_endpoint,
      {
        client_id => $self->client_id,
        resource  => $self->resource_id,
      }
    );

    if (not $device_response->{ success }) {
      Azure::AD::RemoteError->throw(
        message => $device_response->{ content },
        code => 'GetDeviceCodeFailed',
        status => $device_response->{ status }
      );
    }

    return decode_json($device_response->{ content });
  }

  sub get_auth_payload_for {
    my ($self, $device_payload) = @_;

    my $code_expiration = time + $device_payload->{ expires_in };
    my $auth_response;
    while ($code_expiration > time and not $auth_response->{ success }) {
      sleep($device_payload->{ interval });

      $auth_response = $self->ua->post_form(
        $self->token_endpoint,
        {
          grant_type => 'device_code',
          code       => $device_payload->{ device_code },
          client_id  => $self->client_id,
          resource   => $self->resource_id,
        }
      );
    }
 
    if (not $auth_response->{ success }) {
      Azure::AD::RemoteError->throw(
        message => $auth_response->{ content },
        code => 'GetAuthTokenFailed',
        status => $auth_response->{ status }
      );
    }

    return decode_json($auth_response->{content});
  }

  sub _refresh {
    my $self = shift;

    if (not defined $self->current_creds) {
      $self->_refresh_from_cache;
      return $self->current_creds if (defined $self->current_creds);
    }

    return if $self->expiration >= time;

    my $device_payload = $self->get_device_payload;

    $self->message_handler->($device_payload->{ message });

    my $auth = $self->get_auth_payload_for($device_payload);

    $self->current_creds($auth);
    $self->expiration($auth->{ expires_on });
    $self->_save_to_cache;
  }

1;
