package main

// The programs a mandate lists, with every option each one accepts. A name that isn't here asks. Where a
// program has no option that runs code or writes a file, an option that takes a value may be listed as a
// flag: the value then reads as an operand, which is read-only and checked for credential paths and
// addresses like any other word.

// programs on the mandate's list.
var programs = map[string]*cmdSpec{
	// read-only and harmless
	"ls":   {opts: opts(kFlag, "-a -A -l -h -R -1 -t -r -S -d -F -G -i -s -k -n -p -g -o -c -u -U -f -L -H -P -T -@ -e -O -b -q -w -x -C -m -B -X -v -I --all --almost-all --human-readable --recursive --reverse --size --directory --classify --color --group-directories-first --inode --numeric-uid-gid --literal --time --full-time --si --dereference --hide-control-chars --indicator-style --time-style --sort --width --ignore")},
	"cat":  {opts: opts(kFlag, "-n -b -s -v -e -t -u -A -E -T -l --number --number-nonblank --squeeze-blank --show-all --show-ends --show-tabs --show-nonprinting")},
	"head": {numeric: true, opts: opts(kValue, "-n -c --lines --bytes", kFlag, "-q -v --quiet --silent --verbose")},
	"tail": {numeric: true, opts: opts(kValue, "-n -c -s --lines --bytes --sleep-interval --pid", kFlag, "-f -F -q -v -r -b --follow --retry --quiet --silent --verbose")},
	"wc":   {opts: opts(kFlag, "-l -w -c -m -L --lines --words --bytes --chars --max-line-length", kRead, "--files0-from")},
	"grep": {numeric: true, opts: grepOpts},
	"rg":   {opts: rgOpts},
	"diff": {opts: opts(kFlag, "-u -r -N -q -i -w -B -b -y -c -e -s -a -p -T -t -E -Z -d --color --brief --recursive --unified --context --new-file --unidirectional-new-file --report-identical-files --ignore-all-space --ignore-space-change --ignore-case --ignore-blank-lines --side-by-side --text --minimal --no-dereference --strip-trailing-cr --show-c-function --normal --expand-tabs --initial-tab --left-column --suppress-common-lines --speed-large-files --ed --rcs",
		kValue, "-U -C -x -I -L -F -W -X -D --label --exclude --ignore-matching-lines --width --show-function-line --tabsize --starting-file --line-format --new-line-format --old-line-format --unchanged-line-format --ifdef --palette --horizontal-lines",
		kRead, "--from-file --to-file --exclude-from")},
	"cmp":       {opts: opts(kFlag, "-l -s -b --verbose --silent --quiet --print-bytes", kValue, "-i -n --ignore-initial --bytes")},
	"jq":        {opts: jqOpts, check: jqCheck},
	"echo":      {anyOpt: true, operands: []argKind{kValue}}, // every option-looking word is text to print
	"printf":    {anyOpt: true, operands: []argKind{kValue}},
	"pwd":       {opts: opts(kFlag, "-L -P")},
	"which":     {opts: opts(kFlag, "-a -s"), operands: []argKind{kValue}},
	"file":      {opts: opts(kFlag, "-b -i -L -z -h -s -I -d --brief --mime --mime-type --mime-encoding --dereference --uncompress --no-pad", kRead, "-f -m --files-from --magic-file")},
	"stat":      {opts: opts(kFlag, "-L -s -x -n -q -r -l --dereference --terse --file-system", kValue, "-f -c -t --format --printf")},
	"du":        {opts: opts(kFlag, "-s -h -a -c -k -m -g -x -L -P -H -b -A --summarize --human-readable --total --all --apparent-size --one-file-system --dereference --si -0 --null", kValue, "-d -t -B --max-depth --threshold --block-size --exclude --time --time-style", kRead, "--files0-from")},
	"date":      {opts: opts(kFlag, "-u -R -j -n --utc --universal --rfc-2822 --iso-8601 --rfc-3339 --rfc-email -I", kValue, "-d -v -f -z --date", kRead, "-r --reference"), operands: []argKind{kValue}},
	"true":      {anyOpt: true, operands: []argKind{kValue}},
	"false":     {anyOpt: true, operands: []argKind{kValue}},
	"test":      {anyOpt: true, operands: []argKind{kValue}}, // -f, -z and the like are test's own operators
	"basename":  {opts: opts(kFlag, "-a -z --multiple --zero", kValue, "-s --suffix"), operands: []argKind{kValue}},
	"dirname":   {opts: opts(kFlag, "-z --zero"), operands: []argKind{kValue}},
	"realpath":  {opts: opts(kFlag, "-e -m -s -q -z -L -P --canonicalize-existing --canonicalize-missing --no-symlinks --quiet --zero --logical --physical", kValue, "--relative-to --relative-base")},
	"readlink":  {opts: opts(kFlag, "-f -e -m -n -q -s -z --canonicalize --canonicalize-existing --canonicalize-missing --no-newline --quiet --silent --zero")},
	"tr":        {anyOpt: true, operands: []argKind{kValue}}, // the sets may start with a dash
	"cut":       {opts: opts(kValue, "-d -f -c -b --delimiter --fields --characters --bytes --output-delimiter", kFlag, "-s -n -z --complement --only-delimited --zero-terminated")},
	"shasum":    {opts: opts(kValue, "-a --algorithm", kFlag, "-b -c -t -p -s -0 -U --binary --check --text --portable --status --quiet --warn --tag --strict")},
	"sha256sum": {opts: opts(kFlag, "-b -c -t -z --binary --check --text --quiet --status --warn --tag --zero --ignore-missing --strict")},
	"md5":       {opts: opts(kFlag, "-q -r -p -t -x", kValue, "-s")},
	// read, but an option or operand names a file they write
	"sort": {opts: opts(kFlag, "-u -n -r -f -b -d -g -h -i -M -R -V -s -c -C -m -z --unique --numeric-sort --reverse --ignore-case --stable --version-sort --human-numeric-sort --general-numeric-sort --month-sort --random-sort --check --merge --zero-terminated --ignore-leading-blanks --dictionary-order --ignore-nonprinting --debug",
		kValue, "-k -t -S --key --field-separator --buffer-size --parallel --sort", kRead, "--files0-from --random-source", kWrite, "-o -T --output --temporary-directory", kExec, "--compress-program")},
	"uniq": {operands: []argKind{kRead, kWrite}, opts: opts(kFlag, "-c -d -D -i -u -z --count --repeated --all-repeated --ignore-case --unique --zero-terminated --group", kValue, "-f -s -w --skip-fields --skip-chars --check-chars")},
	"xxd": {single: true, operands: []argKind{kRead, kWrite}, opts: opts(kFlag, "-a -b -E -e -i -p -r -u -h -v -C -autoskip -bits -ebcdic -include -plain -ps -postscript -revert -uppercase -capitalize",
		kValue, "-c -cols -g -groupsize -l -len -o -offset -s -seek -n -name -R")},
	"tree": {opts: opts(kFlag, "-a -d -f -i -l -p -s -u -g -h -D -F -q -N -Q -C -n -r -t -v -x -J -X -S --dirsfirst --noreport --prune --du --gitignore --inodes --device --matchdirs --ignore-case --charset --version --fromfile --si --nolinks --filelimit",
		kValue, "-L -P -I -H -T --sort --timefmt --filelimit --charset", kWrite, "-o")},
	"find": {single: true, opts: findOpts},
	// writing: every path inside the directory
	"mkdir": {build: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-p -v --parents --verbose", kValue, "-m --mode")},
	"touch": {build: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-c -a -m -h --no-create --no-dereference", kValue, "-t -d --date", kWrite, "-r --reference")},
	"cp":    {build: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-r -R -p -a -f -v -n -i -l -L -H -P -u -s -x -T -c -b --recursive --preserve --archive --force --verbose --no-clobber --interactive --update --link --symbolic-link --no-target-directory --no-dereference --dereference --backup --parents", kWrite, "-t --target-directory")},
	"mv":    {build: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-f -v -n -i -u -T -h -b --force --verbose --no-clobber --interactive --update --no-target-directory --backup", kWrite, "-t --target-directory")},
	"ln":    {check: lnCheck, operands: []argKind{kValue}, opts: opts(kFlag, "-s -f -n -v -i -h -T -L -P -F --symbolic --force --no-dereference --verbose --interactive --no-target-directory --logical --physical", kWrite, "-t --target-directory")},
	"chmod": {build: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-R -f -v -c -h -H -L -P -x -w -r -X --recursive --verbose --changes --quiet --silent --no-dereference", kWrite, "--reference")},
	"tee":   {build: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-a -i -p --append --ignore-interrupts")},
	"rm":    {build: true, operands: []argKind{kWrite}, check: removeCheck, opts: opts(kFlag, "-r -R -f -v -i -I -d -x --recursive --force --verbose --interactive --dir --one-file-system --preserve-root", kDeny, "--no-preserve-root")},
	"rmdir": {build: true, operands: []argKind{kWrite}, check: removeCheck, opts: opts(kFlag, "-p -v --parents --verbose --ignore-fail-on-non-empty")},
	"cd":    {operands: []argKind{kDir}, check: cdCheck}, // no options: -P and -@ change what the path means
	// builds and tests: they run the project's own code, but every path on the command line stays inside
	// the directory (outside git's own files) and no option names another program to run
	"go":            goSpec,
	"gofmt":         {build: true, single: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-l -w -d -s -e", kValue, "-r", kWrite, "-cpuprofile")},
	"make":          makeSpec,
	"cargo":         cargoSpec,
	"npm":           npmSpec(map[string]*cmdSpec{"test": {}, "run": {}, "ls": {opts: npmListOpts}, "version": {opts: opts(kFlag, "--no-git-tag-version --git-tag-version --allow-same-version", kValue, "-m --message --preid")}}),
	"pnpm":          pnpmSpec,
	"yarn":          yarnSpec,
	"swift":         swiftSpec,
	"pytest":        pytestSpec,
	"git":           gitSpec,
	"golangci-lint": {build: true, subs: map[string]*cmdSpec{"run": {operands: []argKind{kValue}, opts: golangciOpts}, "version": {}, "linters": {}}},
	"staticcheck":   {build: true, single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-tests -show-ignored -list-checks -version -merge", kValue, "-checks -f -go -tags -fail -explain")},
}

var grepOpts = opts(kFlag, "-r -R -n -i -l -L -c -v -w -x -E -F -G -P -o -h -H -s -q -a -I -z -Z -b -T -U -y --color --colour --recursive --dereference-recursive --line-number --ignore-case --no-ignore-case --files-with-matches --files-without-match --count --invert-match --word-regexp --line-regexp --fixed-strings --extended-regexp --basic-regexp --perl-regexp --only-matching --no-filename --with-filename --quiet --silent --no-messages --text --null --null-data --initial-tab --line-buffered --binary --byte-offset",
	kValue, "-e -m -A -B -C -d -D --regexp --max-count --after-context --before-context --context --include --exclude --exclude-dir --include-dir --binary-files --directories --devices --label --group-separator",
	kRead, "-f --file --exclude-from")

var rgOpts = opts(kFlag, "-n -i -S -s -w -l -c -F -x -v -o -N -H -I -u -U -a -q -L -p -P -b --hidden --no-ignore --no-ignore-vcs --no-ignore-parent --no-ignore-global --no-ignore-dot --json --files --files-with-matches --files-without-match --count --count-matches --line-number --no-line-number --ignore-case --smart-case --case-sensitive --word-regexp --fixed-strings --line-regexp --invert-match --only-matching --heading --no-heading --vimgrep --stats --trim --pretty --column --null --no-messages --follow --one-file-system --multiline --multiline-dotall --pcre2 --text --binary --sort-files --no-config --no-filename --with-filename --unrestricted --byte-offset --quiet --version --type-list --no-require-git --glob-case-insensitive",
	kValue, "-e -g -t -T -A -B -C -m -j -M -E -r -d --glob --iglob --type --type-not --max-count --max-depth --max-filesize --context --after-context --before-context --threads --regexp --sort --sortr --encoding --type-add --path-separator --colors --color --replace --field-match-separator --field-context-separator --context-separator --dfa-size-limit --regex-size-limit --max-columns",
	kRead, "-f --file --files-from --ignore-file --pre-glob-file",
	kExec, "--pre --pre-glob --hostname-bin")

// jq --rawfile and --slurpfile name a variable and then a file: both are plain words to the check, which
// already refuses credential paths and addresses in any word.
var jqOpts = opts(kFlag, "-r -c -e -s -S -n -R -a -C -M -j -h --raw-output --compact-output --exit-status --slurp --sort-keys --null-input --raw-input --ascii-output --color-output --monochrome-output --join-output --tab --seq --stream --unbuffered --args --jsonargs --raw-output0",
	kValue, "--indent", kValue2, "--arg --argjson --slurpfile --rawfile", kRead, "-f --from-file -L")

var findOpts = opts(kFlag, "-print -print0 -prune -not -o -a -and -or -depth -d -empty -true -false -xdev -mount -follow -H -L -P -E -s -noleaf -readable -writable -executable -daystart -nouser -nogroup -ls -quit",
	kValue, "-name -iname -path -ipath -wholename -iwholename -regex -iregex -regextype -type -xtype -maxdepth -mindepth -mtime -atime -ctime -mmin -amin -cmin -size -perm -user -group -uid -gid -links -inum -lname -ilname -fstype -printf",
	kRead, "-newer -anewer -cnewer -samefile", kWrite, "-fprint -fprint0 -fls", kExec, "-exec -execdir -ok -okdir", kDeny, "-delete -fprintf")

// ---- go ----

var goBuildOpts = opts(kFlag, "-a -n -race -msan -asan -cover -v -work -x -linkshared -modcacherw -trimpath -json -buildvcs",
	kValue, "-p -covermode -coverpkg -asmflags -buildmode -compiler -gccgoflags -gcflags -installsuffix -ldflags -tags -toolchain",
	kRead, "-pgo", kDir, "-C -modfile -overlay", kWrite, "-o -pkgdir -debug-actiongraph", kExec, "-exec -toolexec")

var goTestOpts = opts(goBuildOpts, kFlag, "-short -failfast -benchmem -c -fullpath",
	kValue, "-vet -list -skip -run -bench -count -timeout -cpu -parallel -shuffle -fuzz -fuzztime -fuzzminimizetime -memprofilerate -blockprofilerate -mutexprofilefraction -testlogfile",
	kWrite, "-coverprofile -cpuprofile -memprofile -blockprofile -mutexprofile -trace -outputdir", kRest, "-args")

var goVetOpts = opts(goBuildOpts, kExec, "-vettool", kFlag, "-all -c -asmdecl -assign -atomic -bools -buildtag -cgocall -composites -copylocks -errorsas -httpresponse -loopclosure -lostcancel -nilfunc -printf -shift -stdmethods -structtag -tests -unmarshal -unreachable -unsafeptr -unusedresult")

var goSpec = &cmdSpec{single: true, build: true, check: goCheck, operands: []argKind{kValue},
	opts: opts(kDir, "-C"),
	subs: map[string]*cmdSpec{
		"build":   {single: true, operands: []argKind{kValue}, opts: goBuildOpts},
		"test":    {single: true, operands: []argKind{kValue}, opts: goTestOpts},
		"vet":     {single: true, operands: []argKind{kValue}, opts: goVetOpts},
		"run":     {single: true, stopAtOperand: true, operands: []argKind{kValue}, opts: goBuildOpts},
		"list":    {single: true, operands: []argKind{kValue}, opts: opts(goBuildOpts, kFlag, "-m -deps -e -test -compiled -export -find -retracted", kValue, "-f")},
		"fmt":     {single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-n -x")},
		"doc":     {single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-all -c -cmd -short -src -u -h")},
		"version": {single: true, operands: []argKind{kRead}, opts: opts(kFlag, "-m -v")},
		"env":     {single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-json -changed", kDeny, "-w -u")},
		"clean":   {single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-i -r -n -x -testcache", kDeny, "-cache -modcache -fuzzcache")},
		"mod": {single: true, subs: map[string]*cmdSpec{
			"tidy":   {single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-v -e", kValue, "-go -compat")},
			"verify": {single: true},
			"vendor": {single: true, opts: opts(kFlag, "-v -e", kWrite, "-o")},
			"graph":  {single: true, opts: opts(kValue, "-go")},
			"why":    {single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-m -vendor")},
			"init":   {single: true, operands: []argKind{kValue}},
			"edit": {single: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-fmt -print -json",
				kValue, "-module -go -require -droprequire -exclude -dropexclude -replace -dropreplace -retract -dropretract -toolchain")},
		}},
		"work": {single: true, subs: map[string]*cmdSpec{
			"init":   {single: true, operands: []argKind{kValue}},
			"use":    {single: true, operands: []argKind{kValue}, opts: opts(kFlag, "-r")},
			"sync":   {single: true},
			"vendor": {single: true, opts: opts(kFlag, "-v", kWrite, "-o")},
			"edit": {single: true, operands: []argKind{kWrite}, opts: opts(kFlag, "-fmt -print -json",
				kValue, "-go -use -dropuse -replace -dropreplace -toolchain -godebug -dropgodebug")},
		}},
		"tool": {single: true, subs: map[string]*cmdSpec{
			"cover": {single: true, opts: opts(kFlag, "-func -html", kRead, "-html -func", kValue, "-mode -var -pkgcfg -outfilelist -p", kWrite, "-o")},
			"pprof": {single: true, opts: opts(kFlag, "-top -tree -text -raw -traces -disasm -peek", kValue, "-list -peek -focus -ignore -show -hide -nodecount -sample_index", kWrite, "-o")},
		}},
	},
}

// ---- make ----

var makeSpec = &cmdSpec{build: true, publish: true, check: makeCheck, operands: []argKind{kValue},
	opts: opts(kFlag, "-k -s -n -B -i -w -r -R -e -q -t -p -d --keep-going --silent --quiet --just-print --dry-run --recon --always-make --ignore-errors --print-directory --no-print-directory --no-builtin-rules --no-builtin-variables --question --touch --debug --print-data-base --warn-undefined-variables --trace --output-sync --environment-overrides",
		kNum, "-j -l --jobs --load-average", kDir, "-C -f -I -W --directory --file --makefile --include-dir --what-if", kExec, "-E --eval")}

// ---- cargo ----

var cargoCommon = opts(kFlag, "--release -r --all-targets --workspace --all --lib --bins --tests --examples --benches --all-features --no-default-features -q --quiet -v --verbose -vv --frozen --locked --offline --keep-going --ignore-rust-version --timings --no-fail-fast --no-deps",
	kValue, "-p --package --features -F --target --bin --example --test --bench --profile -j --jobs --color --message-format --exclude --format-version",
	kDir, "--manifest-path", kWrite, "--target-dir --artifact-dir", kExec, "--config -Z")

func cargoSub(extra ...any) *cmdSpec {
	return &cmdSpec{operands: []argKind{kValue}, opts: opts(append([]any{cargoCommon}, extra...)...)}
}

var cargoSpec = &cmdSpec{build: true, publish: true, subs: map[string]*cmdSpec{
	"build":    cargoSub(),
	"check":    cargoSub(),
	"test":     cargoSub(kFlag, "--no-run --doc"),
	"bench":    cargoSub(kFlag, "--no-run"),
	"run":      cargoSub(),
	"doc":      cargoSub(kFlag, "--document-private-items"),
	"clippy":   cargoSub(kFlag, "--fix --allow-dirty --allow-staged --allow-no-vcs"),
	"fmt":      cargoSub(kFlag, "--check"),
	"tree":     cargoSub(kFlag, "--invert -i --duplicates -d", kValue, "-e --edges --depth --prefix --charset --format -f"),
	"metadata": cargoSub(),
	"clean":    cargoSub(kFlag, "--doc"),
}}

// ---- npm, pnpm, yarn ----

var npmCommon = opts(kFlag, "--silent -s --quiet -q --no-audit --no-fund --no-progress --no-color --no-update-notifier --ignore-scripts --if-present --json --workspaces -ws --include-workspace-root --foreground-scripts --offline --prefer-offline --prefer-online --color",
	kValue, "--loglevel --workspace -w", kDir, "--prefix", kExec, "--script-shell --node-options")

var npmListOpts = opts(kFlag, "--all -a --long -l --prod --production --dev --parseable -p --link", kValue, "--depth --omit --include")

func npmSpec(subs map[string]*cmdSpec) *cmdSpec {
	for _, s := range subs {
		s.operands = []argKind{kValue}
		s.opts = opts(npmCommon, s.opts)
	}
	return &cmdSpec{build: true, publish: true, subs: subs}
}

var pnpmCommon = opts(npmCommon, kFlag, "-r --recursive --workspace-root --frozen-lockfile --prod -P --dev -D --long --parseable --stream --no-bail --parallel --aggregate-output --shell-emulator",
	kValue, "--filter -F --reporter --workspace-concurrency", kDir, "-C --dir")

var pnpmSpec = npmSpec(map[string]*cmdSpec{"test": {opts: pnpmCommon}, "run": {opts: pnpmCommon}, "ls": {opts: pnpmCommon}})

var yarnCommon = opts(npmCommon, kFlag, "--non-interactive --frozen-lockfile --verbose", kDir, "--cwd")

var yarnSpec = npmSpec(map[string]*cmdSpec{"test": {opts: yarnCommon}, "run": {opts: yarnCommon}})

// ---- swift, pytest, linters ----

var swiftCommon = opts(kFlag, "-v --verbose -q --quiet --vv --very-verbose --enable-code-coverage --parallel --show-bin-path --build-tests --skip-update --disable-automatic-resolution --only-use-versions-from-resolved-file --static-swift-stdlib --list-tests -l --enable-test-discovery --disable-index-store --enable-index-store",
	kValue, "-c --configuration --filter --skip --product --target --triple --arch -j --jobs --sanitize --specifier --num-workers", kDir, "--package-path", kWrite, "--build-path --scratch-path --cache-path --xunit-output")

var swiftSpec = &cmdSpec{build: true, subs: map[string]*cmdSpec{
	"build": {operands: []argKind{kValue}, opts: swiftCommon},
	"test":  {operands: []argKind{kValue}, opts: swiftCommon},
	"run":   {operands: []argKind{kValue}, opts: swiftCommon, stopAtOperand: true},
}}

var pytestSpec = &cmdSpec{build: true, check: pytestCheck, operands: []argKind{kValue},
	opts: opts(kFlag, "-q -x -v -s -vv -l --lf --ff --nf --sw --co --collect-only --no-header --disable-warnings --strict-markers --cache-clear --showlocals --setup-show --fixtures --pyargs --cov-append --no-cov --last-failed --failed-first --new-first --quiet --verbose --exitfirst --cov",
		kValue, "-k -m -n -p -o -r -W --maxfail --tb --durations --durations-min --capture --cov-report --cov-fail-under --ignore --ignore-glob --deselect --import-mode --log-level --color --dist --timeout --reruns",
		kDir, "-c --cov-config --rootdir --confcutdir", kWrite, "--basetemp --junitxml --html")}

var golangciOpts = opts(kFlag, "--fix -v --verbose --enable-all --disable-all --fast --new --tests --allow-parallel-runners --print-issued-lines --no-config --show-stats --exclude-use-default --sort-results",
	kValue, "--timeout -E --enable -D --disable -p --presets --new-from-rev --out-format --path-prefix --issues-exit-code --build-tags --max-issues-per-linter --max-same-issues --concurrency -j --skip-dirs --skip-files --color --go",
	kDir, "-c --config", kWrite, "--cpu-profile-path --mem-profile-path --output.text.path --output.json.path --output.tab.path --output.html.path --output.checkstyle.path --output.junit-xml.path --output.sarif.path")
