# Ejecuta makeglossaries para acronimos y glosario
use File::Basename;

add_cus_dep('glo', 'gls', 0, 'run_makeglossaries');
add_cus_dep('acn', 'acr', 0, 'run_makeglossaries');

sub run_makeglossaries {
    my ($base, $path) = fileparse($_[0]);
    pushd $path;
    my $ret = system("makeglossaries", $base);
    popd;
    return $ret;
}

push @generated_exts, 'glo', 'gls', 'glg', 'acn', 'acr', 'alg', 'ist', 'lol';
$pdf_mode = 1;
