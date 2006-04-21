use Module::Build;

my $build = Module::Build->new
(
	module_name => 'Net::SAP',
	license => 'perl',
	script_files => [
		'examples/psapd',
	],
	build_requires => {
		'Module::Build' => '0.20'
	},
	requires => {
		'perl'	=> '5.5.0',
		'Compress::Zlib' => '1.14',
		'Test' => '1.00',
		'Getopt::Std' => 0,
		'Pod::Usage' => 0,
		'Data::Dumper' => 0,
	},
	
	create_makefile_pl => 'passthrough',
	
	recommends => {
		'Net::SDP' => 0,
	},
	include_dirs => [ 'src' ],
	c_source => 'src',
);

$build->create_build_script;
