requires 'Moo';
requires 'Types::Standard';
requires 'HTTP::Tiny';
requires 'IO::Socket::SSL';
requires 'JSON::MaybeXS';
requires 'Path::Class';
requires 'Throwable::Error';

on test => sub {
  requires 'Test::More';
};
