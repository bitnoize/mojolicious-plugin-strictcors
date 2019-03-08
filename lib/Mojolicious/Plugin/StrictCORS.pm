package Mojolicious::Plugin::StrictCORS;
use Mojo::Base "Mojolicious::Plugin";

our $VERSION = "1.01";
$VERSION = eval $VERSION;

sub register {
  my ($self, $app) = @_;

  #
  # Attributes
  #

  $app->attr(cors_origin => sub { [ "*" ] });

  #
  # Helpers
  #

  $app->helper('reply.cors_empty' => sub {
    my ($c, $done) = @_;

    $c->stash(cors_strict => 0) unless $done;
    $c->render(text => "", status => 204);
  });

  $app->helper(cors_necessary => sub {
    my ($c) = @_;

    $c->req->headers->origin ? 1 : 0
  });

  $app->helper(cors_preflight => sub {
    my ($c, @parts) = @_;

    # $api_public->cors("/system" )->to(cors_methods => [ qw/GET/ ])
    # $api_person->cors("/profile")->to(cors_methods => [ qw/PUT/ ])
    map { $_->[0]->cors($_->[2])->to(cors_methods => $_->[1]) } @parts;
  });

  $app->helper(cors_check_origin => sub {
    my ($c) = @_;

    my $cors_origin = $app->cors_origin;
    return unless @$cors_origin; # fail

    my $origin = $c->req->headers->origin;
    return unless $origin; # fail

    my $wildcard = grep { not ref $_ and $_ eq "*" } @$cors_origin;
    return $origin if $wildcard; # success

    my $exists = grep {
      if    (not ref $_)          { $origin eq $_ }
      elsif (ref $_ eq 'Regexp')  { $origin =~ $_ }
      else  { die "API config cors_origin has bad type\n" }
    } @$cors_origin;

    return $origin if $exists; # success

    return; # fail
  } );

  $app->helper(cors_check_methods => sub {
    my ($c) = @_;

    my $cors_methods = $c->stash('cors_methods');
    return unless @$cors_methods; # fail

    my $h = $c->req->headers;

    my $method = $h->header("Access-Control-Request-Method");
    return unless $method; # fail

    my $allow = join ", ", @$cors_methods;

    my $exists = grep { $_ eq $method } @$cors_methods;
    return $allow if $exists; # success

    return; # fail
  } );

  $app->helper(cors_check_headers => sub {
    my ($c) = @_;

    my @cors_headers = qw/Content-Type Authorization Cache-Control/;
    my %cors_headers = map { lc $_ => 1 } @cors_headers;

    my $h = $c->req->headers;

    my $allow = join ", ", @cors_headers;

    my $headers = $h->header("Access-Control-Request-Headers");
    my @headers = split /,\s*/ms, $headers || "";
    return $allow unless @headers; # success

    my $excess = grep { not exists $cors_headers{ lc $_ } } @headers;
    return $allow unless $excess; # success

    return; # fail
  });

  $app->helper(custom_headers => sub {
    my ($c, %headers) = @_;

    my $h = $c->res->headers;

    my $expose = join ", ", keys %headers;

    $h->header($_ => $headers{ $_ }) for keys %headers;
    $h->append("Access-Control-Expose-Headers" => $expose);
  });

  #
  # Hooks
  #

  $app->hook(before_dispatch => sub {
    my ($c) = @_;

    $c->stash(cors_strict => 0);
    $c->stash(cors_origin => undef);
    $c->stash(cors_person => 0);
  });

  $app->hook(after_dispatch => sub {
    my ($c) = @_;

    return unless $c->stash('cors_strict');

    my $cors_origin = $c->stash('cors_origin');
    $c->app->log->debug("Allow Origin '$cors_origin'");

    my $h = $c->res->headers;

    $h->append("Vary" => "Origin");
    $h->header("Access-Control-Allow-Origin" => $cors_origin);

    return unless $c->stash('cors_person');

    $h->header("Access-Control-Allow-Credentials" => "true");
  });

  #
  # Shortcuts
  #

  $app->routes->add_shortcut(under_cors => sub {
    my ($r, @args) = @_;

    $r->under(@args)->to(cb => sub {
      my ($c) = @_;

      # Skip not a CORS request
      return 1 unless $c->cors_necessary;

      my $origin = $c->cors_check_origin;
      return $c->reply->forbidden unless $origin;

      $c->stash(cors_strict => 1);
      $c->stash(cors_origin => $origin);

      return 1; # continue
    });
  });

  $app->routes->add_shortcut(cors => sub {
    my ($r, @args) = @_;

    $r->route(@args)->via('OPTIONS')->to(cb => sub {
      my ($c) = @_;

      return $c->reply->cors_empty unless $c->stash('cors_strict');

      my $cors_methods = $c->cors_check_methods;
      return $c->reply->cors_empty unless $cors_methods;

      my $cors_headers = $c->cors_check_headers;
      return $c->reply->cors_empty unless $cors_headers;

      my $h = $c->res->headers;

      $h->header("Access-Control-Allow-Methods" => $cors_methods);
      $h->header("Access-Control-Allow-Headers" => $cors_headers);
      $h->header("Access-Control-Max-Age" => 3600);

      $c->reply->cors_empty(1);
    });
  });
}

1;
