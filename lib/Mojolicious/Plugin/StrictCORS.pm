package Mojolicious::Plugin::StrictCORS;
use Mojo::Base 'Mojolicious::Plugin';

## no critic
our $VERSION = '1.05_011';
$VERSION = eval $VERSION;
## use critic

use constant DEFAULT_MAX_AGE => 3600;

sub register {
  my ($self, $app, $conf) = @_;

  $conf->{max_age}  //= DEFAULT_MAX_AGE;
  $conf->{expose}   //= [];

  #
  # Helpers
  #

  $app->helper(_cors_check_origin => sub {
    my ($c, @allow) = @_;

    my $origin = $c->req->headers->origin;
    return unless defined $origin;

    return $origin if grep { not ref $_ and $_ eq '*' } @allow;

    return $origin if grep {
      if    (not ref $_)          { lc $origin eq lc $_ }
      elsif (ref $_ eq 'Regexp')  { $origin =~ $_ }
      else  { die "Wrong router config 'cors_origin'" }
    } @allow;

    $c->app->log->debug("Reject CORS Origin '$origin'");

    return;
  });

  $app->helper(_cors_check_methods => sub {
    my ($c, @allow) = @_;

    my $method = $c->req->headers->header('Access-Control-Request-Method');
    return unless defined $method;

    my $allow = join ", ", @allow;

    return $allow if grep {
      if    (not ref $_)  { uc $method eq uc $_ }
      else  { die "Wrong router config 'cors_methods'" }
    } @allow;

    $c->app->log->debug("Reject CORS Method '$method'");

    return;
  });

  $app->helper(_cors_check_headers => sub {
    my ($c, @allow) = @_;

    my @safe_headers = qw/
      Cache-Control
      Content-Language
      Content-Type
      Expires
      Last-Modified
      Pragma
    /;

    my %safe_headers = map { lc $_ => 1 } @safe_headers;
    my $allow = join ", ", @allow;

    my $headers = $c->req->headers->header('Access-Control-Request-Headers');
    my @headers = map { lc } grep { $_ } split /,\s*/ms, $headers || '';

    return $allow unless @headers;

    return $allow unless grep {
      if    (not ref $_)  { not $safe_headers{ lc $_ } }
      else  { die "Wrong router config 'cors_headers'" }
    } @allow;

    $c->app->log->debug("Reject CORS Headers '$headers'");

    return;
  });

  #
  # Hooks
  #

  $app->hook(around_action => sub {
    my ($next, $c, $action, $last) = @_;

    # Only endpoints intrested
    return $next->() unless $last;

    # Do not process preflight requests
    return $next->() if $c->req->method eq 'OPTIONS';

    my $opts = _route_opts($c->match->endpoint);

    my @opts_origin = @{$opts->{origin} //= []};
    return $next->() unless @opts_origin;

    my $h = $c->res->headers;
    $h->append('Vary' => 'Origin');

    my $origin = $c->_cors_check_origin(@opts_origin);
    return $next->() unless defined $origin;

    $h->header('Access-Control-Allow-Origin' => $origin);

    $h->header('Access-Control-Allow-Credentials' => 'true')
      if $opts->{credentials} //= 0;

    my @opts_expose = (@{$conf->{expose}}, @{$opts->{expose} //= []});
    if (@opts_expose) {
      my $opts_expose = join ", ", @opts_expose;
      $h->header('Access-Control-Expose-Headers' => $opts_expose);
    }

    $c->app->log->debug("Allow CORS Origin '$origin'");

    return $next->();
  });

  #
  # Shortcuts
  #

  # CORS Under
  $app->routes->add_shortcut(under_cors => sub {
    my ($r, @args) = @_;

    $r->under(@args)->to(
      cb => sub {
        my ($c) = @_;

        # Not a CORS request, success
        return 1 unless defined $c->req->headers->origin;

        my $opts = _route_opts($c->match->endpoint);

        # Route configured for CORS, success
        return 1 if @{$opts->{origin} //= []};

        $c->render(status => 403, text => "CORS Forbidden");
        $c->app->log->debug("Forbidden CORS request");

        return;
      }
    );
  });

  # CORS Preflight
  $app->routes->add_shortcut(cors => sub {
    my ($r, @args) = @_;

    $r->route(@args)->options->over(
      headers => {
        'Origin' => qr/\S/ms,
        'Access-Control-Request-Method' => qr/\S/ms
      }
    )->to(
      cb => sub {
        my ($c) = @_;

        my $opts = _route_opts($c->match->endpoint);

        my @opts_origin = @{$opts->{origin} //= []};
        return $c->render(status => 204, data => '')
          unless @opts_origin;

        my $h = $c->res->headers;
        $h->append('Vary' => 'Origin');

        my $origin = $c->_cors_check_origin(@opts_origin);
        return $c->render(status => 204, data => '')
          unless defined $origin;

        my @opts_methods = @{$opts->{methods} //= []};
        push @opts_methods, 'HEAD'
          if grep { uc $_ eq 'GET' } @opts_methods
            and not grep { uc $_ eq 'HEAD' } @opts_methods;
        return $c->render(status => 204, data => '')
          unless @opts_methods;

        my $methods = $c->_cors_check_methods(@opts_methods);
        return $c->render(status => 204, data => '')
          unless defined $methods;

        my @opts_headers = @{$opts->{headers} //= []};

        my $headers = $c->_cors_check_headers(@opts_headers);
        return $c->render(status => 204, data => '')
          unless defined $headers;

        $h->header('Access-Control-Allow-Origin'  => $origin);
        $h->header('Access-Control-Allow-Methods' => $methods);

        $h->header('Access-Control-Allow-Headers' => $headers)
          if $headers;

        $h->header('Access-Control-Allow-Credentials' => 'true')
          if $opts->{credentials} //= 0;

        $h->header('Access-Control-Max-Age' => $conf->{max_age});

        $c->app->log->debug("Accept CORS '$origin' => '$methods'");

        return $c->render(status => 204, data => '');
      }
    );
  });
}

sub _route_opts {
  my ($route) = @_;

  my %opts;

  my @fields = qw/origin credentials expose methods headers/;

  while ($route) {
    for my $name (@fields) {
      next if exists $opts{$name};
      next unless exists $route->to->{"cors_$name"};

      $opts{$name} = $route->to->{"cors_$name"}
    }

    $route = $route->parent;
  }

  return \%opts;
}

1;

__END__

=encoding utf8

=head1 NAME

Mojolicious::Plugin::StrictCORS - Strict and secure control over CORS

=head1 VERSION

1.05

=head1 SYNOPSIS

  # Mojolicious app
  sub startup {
    my ($app) = @_;

    # load and configure
    $app->plugin('StrictCORS');
    $app->plugin('StrictCORS', {
      max_age => -1,
      expose  => ['X-Message']
    });

    # set app-wide CORS defaults
    $app->routes->to('cors_credentials' => 1);

    # set default CORS options for nested routes
    $r = $r->under(..., { 'cors_origin' => ['*'] }, ...);

    # set CORS options for this route (at least "origin" option must be
    # defined to allow CORS, either here or in parent routes)
    $r->get(..., { 'cors_origin' => ['*'] }, ...);
    $r->route(...)->to('cors_origin' => ['*']);

    # allow non-simple (with preflight) CORS on this route
    $r->cors(...);

    # create under to protect all nested routes
    $r = $app->routes->under_cors("/v1");

=head1 DESCRIPTION

L<Mojolicious::Plugin::StrictCORS> is a plugin that allow you to configure
Cross Origin Resource Sharing for routes in L<Mojolicious> app.

Implements this spec: L<http://www.w3.org/TR/2014/REC-cors-20140116/>.

This module is based on Powerman's CORS implementation:
https://github.com/powerman/perl-Mojolicious-Plugin-SecureCORS
But this module no longer updated, so this one wos created.

=head2 SECURITY

Don't use the lazy C<< 'cors_origin' => ['*'] >> for resources which should be
available only for intranet or which behave differently when accessed from
intranet - otherwise malicious website opened in browser running on
workstation in intranet will get access to these resources.

Don't use the lazy C<< 'cors_origin' => ['*'] >> for resources which should be
available only from some known websites - otherwise other malicious website
will be able to attack your site by injecting JavaScript into the victim's
browser.

Consider using C<under_cors()> - it won't "save" you but may helps.

=head1 INTERFACE

=head2 CORS options

To allow CORS on some route you should define relevant CORS options for
that route. These options will be processed automatically using
L<Mojolicious/"around_action"> hook and result in adding corresponding HTTP
headers to the response.

Options should be added into default parameters for the route or it parent
routes. Defining CORS options on parent route allow you to set some
predefined defaults for their nested routes.

=over

=item C<< 'cors_origin' => ['*'] >>

=item C<< 'cors_origin' => ["http://example.com"] >>

=item C<< 'cors_origin' => ["https://example.com", "http://example.com:8080"] >>

=item C<< 'cors_origin' => [qr/\.local\z/ms] >>

=item C<< 'cors_origin' => undef >> (default)

This option is required to enable CORS support for the route.

Only matched origins will be allowed to process returned response
(C<['*']> will match any origin).

When set to undef no origins will match, so it effectively disable
CORS support (may be useful if you've set this option value on parent
route).

=item C<< 'cors_credentials' => 1 >>

=item C<< 'cors_credentials' => undef >> (default)

While handling preflight request true/false value will tell browser to
send or not send credentials (cookies, http auth, SSL certificate) with
actual request.

While handling simple/actual request if set to false and browser has sent
credentials will disallow to process returned response.

=item C<< 'cors_expose' => ['X-Some'] >>

=item C<< 'cors_expose' => [qw/X-Some X-Other Server/] >>

=item C<< 'cors_expose' => undef >> (default)

Allow access to these headers while processing returned response.

These headers doesn't need to be included in this option:

  Cache-Control
  Content-Language
  Content-Type
  Expires
  Last-Modified
  Pragma

=item C<< 'cors_headers' => ['X-Requested-With'] >>

=item C<< 'cors_headers' => [qw/X-Requested-With Content-Type X-Some/] >>

=item C<< 'cors_headers' => undef >> (default)

Define headers which browser is allowed to send. Work only for non-simple
CORS because it require preflight.

=item C<< 'cors_methods' => ['POST'] >>

=item C<< 'cors_methods' => [qw/GET POST PUT DELETE] >>

This option can be used only for C<cors()> route. It's needed in complex
cases when it's impossible to automatically detect CORS option while
handling preflight - see below for example.

=back

=head2 cors

    $app->routes->cors(...);

Accept same params as L<Mojolicious::Routes::Route/"route">.

Add handler for preflight (OPTIONS) CORS request - it's required to allow
non-simple CORS requests on given path.

To be able to respond on preflight request this handler should know CORS
options for requested method/path. In most cases it will be able to detect
them automatically by searching for route defined for same path and HTTP
method given in CORS request. Example:

    $r->cors("/rpc");
    $r->get("/rpc", { 'cors_origin' => ["http://example.com"] });
    $r->put("/rpc", { 'cors_origin' => [qr/\.local\z/ms] });

But in some cases target route can't be detected, for example if you've
defined several routes for same path using different conditions which
can't be checked while processing preflight request because browser didn't
sent enough information yet (like C<Content-Type:> value which will be
used in actual request). In this case you should manually define all
relevant CORS options on preflight route - in addition to CORS options
defined on target routes. Because you can't know which one of defined
routes will be used to handle actual request, in case they use different
CORS options you should use combined in less restrictive way options for
preflight route. Example:

    $r->cors("/rpc")->to(
        'cors_methods'      => [qw/GET POST/],
        'cors_origin'       => ["http://localhost", "http://example.com"],
        'cors_credentials'  => 1,
    );
    $r->any([qw(GET POST)] => "/rpc")->over(
      headers => {
        'Content-Type' => 'application/json-rpc'
      }
    )->to(
      controller    => 'jsonrpc',
      action        => 'handler',

      'cors_origin' => ["http://localhost"]
    );
    $r->post("/rpc")->over(
      headers => {
        'Content-Type' => 'application/soap+xml'
      }
    )->to(
      controller  => 'soaprpc',
      action      => 'handler',

      'cors_origin'       => "http://example.com",
      'cors_credentials'  => 1
    );

This route use 'headers' condition, so you can add your own handler for
OPTIONS method on same path after this one, to handle non-CORS OPTIONS
requests on same path.

=head2 under_cors

    $route = $app->routes->under_cors(...)

Accept same params as L<Mojolicious::Routes::Route/"under">.

Under returned route CORS requests to any route which isn't configured
for CORS (i.e. won't have C<'cors_origin'> in route's default parameters)
will be rendered as "403 Forbidden".

This feature should make it harder to attack your site by injecting
JavaScript into the victim's browser on vulnerable website. More details:
L<https://code.google.com/p/html5security/wiki/CrossOriginRequestSecurity#Processing_rogue_COR:>.

=head1 OPTIONS

L<Mojolicious::Plugin::StrictCORS> supports the following options.

=head2 max_age

  $app->plugin('StrictCORS', { max_age => -1 });

Value for C<Access-Control-Max-Age:> sent by preflight OPTIONS handler.
If set to C<-1> cache will be disabled.

Default is 3600 (1 hour).

=head2 expose

  $app->plugin('StrictCORS', { expose => ['X-Message']});

Default value for C<Access-Control-Expose-Headers> for all requests, that
configured to use CORS.

Defailt is ampty array.

=head1 METHODS

L<Mojolicious::Plugin::StrictCORS> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);
  $plugin->register(Mojolicious->new, { max_age => -1 });

Register hooks in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>.

=head1 SUPPORT

=head2 Bugs / Feature Requests

Bugs should always be submitted via the GitHub bug tracker.

L<https://github.com/bitnoize/mojolicious-plugin-strictcors/issues>

=head2 Source Code

Feel free to fork the repository and submit pull requests.

L<https://github.com/bitnoize/mojolicious-plugin-strictcors>

=head1 AUTHOR

Dmitry Krutikov E<lt>monstar@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2020 Dmitry Krutikov.

You may distribute under the terms of either the GNU General Public
License or the Artistic License, as specified in the README file.

=cut
