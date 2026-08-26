<?php
require_once __DIR__ . '/afs_contract.php';

/*
 * Copyright (c) 2005 - 2009 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

//require_once( 'config.php' );
//require_once( 'mime.php' );
//require_once( 'session.php' );
define( "CLIPSEPARATOR", "*#~!@@@" );

if ( !extension_loaded( 'posix' )) {
    error_log( "Couldn't load necessary posix function" );
    echo "<p>Couldn't load necessary posix function</p>\n";
    exit( 1 );
}

/*
if ( !extension_loaded( 'filedrawers' )) {
    error_log( "Couldn't load Filedrawers PECL extension" );
    echo "<p>Couldn't load necessary Filedrawers extension</p>\n";
    exit( 1 );
}
*/

// remember this class needs to have $this->path set
class Afs
{
    protected $selectedItems;
    protected $afsUtils   = '/usr/bin';
    protected $afsRoot    = '/afs';
    public  $confirmMsg   = '';
    public  $errorMsg     = '';
    public  $notifyMsg    = '';
    public  $parPath;     // Path to the parent of current path
    public  $filename     = '';
    public  $adminPriv    = 0;
    public  $deletePriv   = 0;
    public  $insertPriv   = 0;
    public  $lockPriv     = 0;
    public  $lookupPriv   = 0;
    public  $readPriv     = 0;
    public  $writePriv    = 0;
    public  $path         = '';
    public  $sid          = '';
    public  $type         = '';
    public  $mimetype     = '';
    public  $formKey      = '';
    private $uniqname     = '';
    protected $afsStat;
    protected $afsAvailable = false;
    protected $credentialIdentity = '';
    protected $lastFsStatus = 0;
    protected $newName    = '';
    protected $originPath = '';
    protected $startCWD   = '';

    public function __construct( $path="" )
    {
        $this->uniqname = isset( $_SERVER['REMOTE_USER'] )
            ? $_SERVER['REMOTE_USER'] : '';
        $this->credentialIdentity = $this->uniqname;
        $this->startCWD = getcwd();
        $this->afsStat  = @stat( $this->afsRoot );

        // Bug 2634811 Fixed: Make sure /afs isn't on the local filesystem
        $rootStat = @stat( '/' );

        if ( !is_array( $this->afsStat ) || !is_array( $rootStat )
          || $this->afsStat['dev'] == $rootStat['dev'] ) {
            error_log( "$this->afsRoot is unavailable or has the same device ID as / " .
                "(is afs actually mounted?): $this->uniqname, " .
                "$this->errorMsg " . __FILE__ );
            $this->errorMsg = 'AFS is not mounted.';
            return;
        }

        $this->afsAvailable = true;

        // Bug 1975875 Fixed: Don't trim whitespaces from path
        if ( !$this->setPath( $path )) {
            return;
        }

        // Generate the path of the folder one level above the current
        if ( !preg_match( "/(.*\/)([^\/]+)\/?$/", $this->path, $Matches )) {
            error_log( "missing homedir: [$this->path] $this->uniqname, " .
                "$this->errorMsg " . __FILE__ );
            $this->errorMsg = 'Missing home directory.';
            return;
        }
        $this->parPath  = $Matches[1];
        $this->filename = $Matches[2];

        if ( !isset( $_SESSION['formKey'] )) {
            $_SESSION['formKey'] = md5( uniqid( rand(), true ));
        }

        $this->formKey = $_SESSION['formKey'];
        $this->sid     = md5( uniqid( rand(), true ));
    }


    // Symlink safe method to determine file type
    public function getType()
    {
        if ( !$this->makePathAFSlocal( dirname( $this->path ))) {
            return false;
        }

        clearstatcache();
        if ( @filetype( basename( $this->path )) == 'dir' ) {
            @chdir( $this->startCWD );
            return 'dir';
        } else {
            clearstatcache();
            $type = @filetype( basename( $this->path ));

            if ( $type == 'file' ) {
                $this->mimetype = function_exists( 'fm_get_mime_type' )
                    ? fm_get_mime_type( basename( $this->path ))
                    : 'application/octet-stream';
                @chdir( $this->startCWD );
                return $type;
            } else {
                @chdir( $this->startCWD );
                return 'none';
            }
        }

        @chdir( $this->startCWD );
    }


    public function processCommand()
    {
        if ( !isset( $_POST['command'] ) || $this->formKey != $_POST['formKey'] ) {
            return false;
        }

        $this->setSelectedItems();

        switch ( $_POST['command'] ) {
            case 'newfolder':
                $this->createFolder();
                break;
            case 'rename':
                $this->setNewItemName();
                $this->afsRename();
                break;
            case 'cut':
                $this->setOriginPath();
                $this->moveFiles();
                break;
            case 'copy':
                $this->setOriginPath();
                $this->copyFiles();
                break;
            case 'delete':
                $this->deleteFiles();
                break;
            default:
                break;
        }
    }


    /*
     * This function sets the "target" of an operation
     * (what file(s) or folder(s)
     * to perform the selected action on.
     */
    protected function setSelectedItems()
    {
        if ( isset( $_POST['selectedItems'] )
          && is_array( $_POST['selectedItems'] )) {
            $this->selectedItems = array();

            foreach ( $_POST['selectedItems'] as $key=>$item ) {
                $this->selectedItems[$key] = $item;
            }
        } else if ( isset( $_POST['selectedItems'] )) {
            $this->selectedItems = $_POST['selectedItems'];
        }
    }


    // Some functions like cut or paste need to know where a file is coming from
    // in addition to where it is going
    public function setOriginPath()
    {
        if ( isset( $_POST['originPath'] )) {
            $this->originPath = $this->pathSecurity( $_POST['originPath'] );
        }
    }


    public function setNewItemName()
    {
        if ( isset( $_POST['newName'] )) {
            $this->newName = $_POST['newName'];
        }
    }


    public function createFolder()
    {
        if ( !$this->makePathAFSlocal( $this->path )) {
            return false;
        }

        if ( $this->selectedItems != 'Please enter a name for your new folder.' ) {
            if ( $this->linkSafeFileExists( basename( $this->selectedItems ))) {
                $this->errorMsg = "The folder \'$this->selectedItems\' " .
                    "already exists. Please select a different name.";
                  @chdir( $this->startCWD );
                  return false;
            }

            if ( !mkdir( trim( basename( $this->selectedItems )), 0755, true )) {
                $this->errorMsg = 'Unable to create folder.';
                @chdir( $this->startCWD );
                return false;
            }

            @chdir( $this->startCWD );
            return true;
        }
    }


    // Remove an existing folder
    // jackylee at eml dot cc
    public function removeFolder( $folderPath )
    {
        if ( !$this->makePathAFSlocal( $folderPath )) {
            return false;
        }

        if ( !$handle = @opendir( '.' )) {
            $this->errorMsg = 'Unable to remove the folder because ' .
                'it no longer exists.';
            @chdir( $this->startCWD );
            return false;
        }

        while ( false !== ( $item = readdir( $handle ))) {

            if ( $item == "." || $item == ".." ) {
                continue;
            }

            $itemPath = $folderPath . '/' . $item;

            if ( is_dir( $itemPath ) && !is_link( $itemPath )) {
                if ( !$this->removeFolder( $itemPath )) {
                    @chdir( $this->startCWD );
                    return false;
                }
            } else {
                if ( !$this->makePathAFSlocal( $folderPath )) {
                    @chdir( $this->startCWD );
                    return false;
                }

                unlink( basename( $item ));
                @chdir( $this->startCWD );
            }
        }

        closedir( $handle );

        if ( !$this->makePathAFSlocal( $folderPath )) {
            @chdir( $this->startCWD );
            return false;
        }

        if ( rmdir( '../' . basename( getcwd()))) {
            $this->notifyMsg = "Successfully deleted file(s).";
            @chdir( $this->startCWD );
            return true;
        }

        @chdir( $this->startCWD );
        $this->errorMsg = 'Unable to remove the folder.';
        return false;
    }


    // Delete specified files
    public function deleteFiles()
    {
        if ( ! $this->selectedItems ) {
            return false;
        }

        // XXX 0.5.0 should use a data structure that doesn't require splitting
        // on a whitespace character
        $files = explode( "\n", $this->selectedItems );

        foreach ( $files as $file ) {
            $file = preg_replace( "/[\r\n]/", '', $file );

            if ( empty( $file )) {
                continue;
            }

            // Security checks are in Afs::removeFolder()
            $itemPath = $this->path . '/' . $file;

            if ( is_dir( $itemPath ) && !is_link( $itemPath )) {
                if ( !$this->removeFolder( $itemPath )) {
                    return false;
                }
            } else {
                if ( !$this->makePathAFSlocal( $this->path )) {
                    return false;
                }

                if ( !@unlink( basename( $file ))) {
                    @chdir( $this->startCWD );
                    $this->errorMsg = "Unable to delete $file.";
                    return false;
                } else {
                    @chdir( $this->startCWD );
                    $this->notifyMsg = "Successfully deleted file(s).";
                }
            }
        }

        @chdir( $this->startCWD );
        return true;
    }


    public function afsRename()
    {

        if ( $this->selectedItems == $this->newName ) {
            return false;
        }

        if ( !$this->makePathAFSlocal( $this->path )) {
            return false;
        }

        if ( is_link( basename( $this->selectedItems ))) {
            $this->errorMsg = "Symbolic links cannot be renamed.";
            @chdir( $this->startCWD );
            return false;
        }

        $newName = trim( basename( $this->newName ));

        if ( $this->linkSafeFileExists( $newName )) {
            $this->errorMsg = "The file or folder '" . $newName .
                "' already exists. Please select a different name.";
            @chdir( $this->startCWD );
            return false;
        }

        if ( !function_exists( 'filedrawers_rename' )) {
            $this->errorMsg = 'AFS-safe rename support is unavailable.';
            @chdir( $this->startCWD );
            return false;
        }

        if ( !@filedrawers_rename( basename( $this->selectedItems ),
                $newName, $this->afsRoot )) {
            $this->errorMsg = 'Unable to rename this file or folder.';
            @chdir( $this->startCWD );
            return false;
        }

        @chdir( $this->startCWD );
        return true;
    }

    /*
     * Move files from one directory to another
     * This will clobber an existing file with the same name
     */
    function moveFiles()
    {
        $files = explode( CLIPSEPARATOR, $this->selectedItems );

        foreach ( $files as $file ) {
            if ( empty( $file )) {
                continue;
            }

            // Security checks are in filedrawers_rename
            $sourcePath = $this->originPath . '/' . $file;
            $destPath   = $this->path . '/' . $file;

            if ( !function_exists( 'filedrawers_rename' )) {
                $this->errorMsg = 'AFS-safe move support is unavailable.';
                return false;
            }

            if ( !@filedrawers_rename( $sourcePath, $destPath, $this->afsRoot )) {
                $this->errorMsg = "Unable to move: $file.";
                return false;
            }

            $this->notifyMsg = "Pasted the contents of the clipboard.";
        }

        return true;
    }

    // Copy file from one directory to another
    function copyFiles()
    {
        $files = explode( CLIPSEPARATOR, $this->selectedItems );

        foreach ( $files as $file ) {
            if ( empty( $file )) {
                continue;
            }

            // Link-safe dispatch and security checks are in copyItem().
            $sourcePath = $this->originPath . '/'. $file;
            $destPath   = $this->path . '/' . $file;

            if ( !$this->copyItem( $sourcePath, $destPath )) {
                $this->errorMsg = "Unable to copy $file.";
                return false;
            }

            $this->notifyMsg = "Pasted the contents of the clipboard.";
        }

        return true;
    }


    // Dispatch links before directory checks so a directory symlink is copied
    // as a link and is never traversed by copy_dirs().
    protected function copyItem( $source, $target )
    {
        if ( is_link( $source )) {
            return $this->copy( $source, $target );
        }

        $type = @filetype( $source );
        if ( $type === 'dir' ) {
            return $this->copy_dirs( $source, $target );
        }
        if ( $type === 'file' ) {
            return $this->copy( $source, $target );
        }

        return false;
    }


    /* A helper function for copyFiles().  Copies an entire directory at once.
     * Original author: swizec at swizec dot com, php.net
     */
    public function copy_dirs( $source, $target )
    {
        if ( is_link( $source ) || !is_dir( $source )) {
            return false;
        }

        $sourceReal = @realpath( $source );
        $targetParentReal = @realpath( dirname( $target ));
        if ( $sourceReal === false || $targetParentReal === false ) {
            return false;
        }

        $sourcePrefix = rtrim( $sourceReal, '/' ) . '/';
        $targetParentPrefix = rtrim( $targetParentReal, '/' ) . '/';
        if ( $targetParentReal === $sourceReal
          || strpos( $targetParentPrefix, $sourcePrefix ) === 0 ) {
            return false;
        }

        if ( !$this->makePathAFSlocal( dirname( $target ))) {
            return false;
        }

        $targetCheck = getcwd();

        if ( !@mkdir( basename( $target ), 0755 )) {
            @chdir( $this->startCWD );
            return false;
        }

        if ( !$this->makePathAFSlocal( $source )) {
            @chdir( $this->startCWD );
            return false;
        }

        $destCheck = getcwd();

        // Prevent copying directory inside of itself
        if ( $targetCheck == $destCheck ) {
            @chdir( $this->startCWD );
            return false;
        }

        $dir = dir( '.' );

        while ( false !== ( $entry = $dir->read())) {
            if ( $entry == '.' || $entry == '..' ) {
                continue;
            }

            $sourcePath = $source . '/' . $entry;
            $targetPath = $target . '/' . $entry;

            // Link-safe dispatch and security checks are in copyItem().
            if ( !$this->copyItem( $sourcePath, $targetPath )) {
                @chdir( $this->startCWD );
                return false;
            }
        }

        $dir->close();
        @chdir( $this->startCWD );
        return true;
    }


    /* An AFS safe version of the PHP copy builtin - this will only copy
     * a file with a source and destination in AFS.  If we relied on the
     * copy builtin, there is a small possibility of a race condition where
     * the copy could be symlink'ed out of AFS.  This function works on file
     * handles only after making sure the source and destination are in AFS.
     */
    public function copy( $source, $dest )
    {
        if ( !$this->afsAvailable || !is_array( $this->afsStat )) {
            return false;
        }

        if ( is_link( $source )) {
            if ( !$this->makePathAFSlocal( dirname( $source ))) {
                return false;
            }

            $name   = basename( $source );
            $target = readlink( $name );

            if ( !$this->makePathAFSlocal( dirname( $dest ))) {
                @chdir( $this->startCWD );
                return false;
            }

            if ( !symlink( $target, basename( $dest ))) {
                @chdir( $this->startCWD );
                return false;
            }

            @chdir( $this->startCWD );
            return true;
        }

        if ( !( $sourceHdl = @fopen( $source, "rb" ))) {
            @chdir( $this->startCWD );
            return false;
        }

        $sourceStat = fstat( $sourceHdl );

        if ( !is_array( $sourceStat )
          || $sourceStat['dev'] != $this->afsStat['dev'] ) {
            @fclose( $sourceHdl );
            @chdir( $this->startCWD );
            return false;
        }

        if ( !$this->makePathAFSlocal( dirname( $dest ))) {
            @fclose( $sourceHdl );
            @chdir( $this->startCWD );
            return false;
        }

        // If you want copy to overwrite, then do unlink(basename($dest)) here
        if ( !( $destHdl = @fopen( basename( $dest ), "xb" ))) {
            @fclose( $sourceHdl );
            @chdir( $this->startCWD );
            return false;
        }

        $copied = true;
        while ( !feof( $sourceHdl )) {
            $buffer = fread( $sourceHdl, 1024 * 1024 );
            if ( $buffer === false ) {
                $copied = false;
                break;
            }

            $written = 0;
            $length = strlen( $buffer );
            while ( $written < $length ) {
                $bytes = fwrite( $destHdl, substr( $buffer, $written ));
                if ( $bytes === false || $bytes === 0 ) {
                    $copied = false;
                    break 2;
                }
                $written += $bytes;
            }
        }

        if ( !@fflush( $destHdl )) {
            $copied = false;
        }
        @fclose( $sourceHdl );
        if ( !@fclose( $destHdl )) {
            $copied = false;
        }

        if ( !$copied ) {
            @unlink( basename( $dest ));
        }
        @chdir( $this->startCWD );

        return $copied;
    }


    // A AFS safe version of the PHP readfile builtin - this will only
    // read files which are hosted in AFS.
    function readfile()
    {
        if ( !$this->afsAvailable || !is_array( $this->afsStat )) {
            return false;
        }

        clearstatcache();

        if ( $handle = @fopen( $this->path, "rb" )) {
            $stat = fstat( $handle );
            if ( is_array( $stat ) && $stat['dev'] == $this->afsStat['dev'] ) {
                while ( !feof( $handle )) {
                    $buffer = fread( $handle, 1024 * 1024 );
                    if ( $buffer === false ) {
                        @fclose( $handle );
                        return false;
                    }
                    echo $buffer;
                }
                @fclose( $handle );
                return true;
            }

            @fclose( $handle );
        }

        return false;
    }

    // Change the ACL for a given path
    function changeAcl($entity,
                       $rights,
                       $path='',
                       $recursive=false,
                       $negative=false )
    {
        $path = ( $path ) ? $path : $this->path;
        $path = $this->pathSecurity( $path );
        $rights = trim( $rights );

        if ( !$path || empty( $entity )
          || !preg_match( '/^(none|[lrwidkaA-H]{1,15})$/', $rights )) {
            $this->errorMsg =
                'Warning: Invalid access control list request.';
            return false;
        }

        if ( !$recursive ) {
            return $this->changeAclEntries(
                array( $entity => $rights ), $path, $negative );
        }

        $paths = array( $path );
        if ( $recursive && is_dir( $path )) {
            $flags = FilesystemIterator::SKIP_DOTS;
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $path, $flags ),
                RecursiveIteratorIterator::SELF_FIRST );

            foreach ( $iterator as $item ) {
                if ( $item->isDir() && !$item->isLink()) {
                    $safePath = $this->pathSecurity( $item->getPathname());
                    if ( !$safePath ) {
                        return false;
                    }
                    $paths[] = $safePath;
                }
            }
        }

        foreach ( $paths as $aclPath ) {
            $arguments = array( 'sa' );
            if ( $negative ) {
                $arguments[] = '-negative';
            }
            $arguments[] = $aclPath;
            $arguments[] = $entity;
            $arguments[] = $rights;

            $result = $this->runFs( $arguments );
            if ( $result === false || $this->lastFsStatus !== 0
              || preg_match( '/(^|\n)fs:/', $result )) {
                $this->errorMsg =
                    'Warning: Unable to modify the access control list.';
                return false;
            }
        }

        return true;
    }

    // Change multiple ACL entries in one fs invocation to avoid per-ACE
    // partial updates and subprocess overhead.
    function changeAclEntries( $entries, $path='', $negative=false )
    {
        $path = ( $path ) ? $path : $this->path;
        $path = $this->pathSecurity( $path );
        if ( !$path || !is_array( $entries ) || empty( $entries )) {
            return false;
        }

        $arguments = array( 'sa' );
        if ( $negative ) {
            $arguments[] = '-negative';
        }
        $arguments[] = $path;

        foreach ( $entries as $entity => $rights ) {
            $rights = trim( $rights );
            if ( $entity === ''
              || !preg_match( '/^(none|[lrwidkaA-H]{1,15})$/', $rights )) {
                $this->errorMsg =
                    'Warning: Invalid access control list request.';
                return false;
            }
            $arguments[] = $entity;
            $arguments[] = $rights;
        }

        $result = $this->runFs( $arguments );
        if ( $result === false || $this->lastFsStatus !== 0
          || preg_match( '/(^|\n)fs:/', $result )) {
            $this->errorMsg =
                'Warning: Unable to modify the access control list.';
            return false;
        }

        return true;
    }

    // Return an array of ACL rights for the current path
    function readAcl( $path='' )
    {
        $path = ( $path ) ? $path : $this->path;
        $path = $this->pathSecurity( $path );
        if ( !$path ) {
            return false;
        }

        $result = $this->runFs( array( 'listacl', $path ));
        if ( $result === false || $this->lastFsStatus !== 0
          || preg_match( '/(^|\n)fs:/', $result )) {
            $this->errorMsg =
                'Warning: Unable to read the access control list.';
            return false;
        }

        $acl = $this->parseAclOutput( $result );
        if ( $acl === false ) {
            $this->errorMsg =
                'Warning: Unable to parse the access control list.';
        }

        return $acl;
    }

    public function parseAclOutput( $result )
    {
        if ( !is_string( $result )) {
            return false;
        }

        $rights = array( 'l', 'r', 'w', 'i', 'd', 'k', 'a',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' );
        $acl = array(
            'normal' => array(),
            'negative' => array(),
            'inherited' => false
        );
        $section = '';
        $sawHeader = false;
        $sawNormal = false;
        $sawNegative = false;
        $lines = preg_split( '/\r?\n/', $result );

        foreach ( $lines as $line ) {
            $line = trim( $line );
            if ( $line === '' ) {
                continue;
            }
            if ( preg_match( '/^Access list( \(inherited\))? for .+ is$/i',
                    $line, $header )) {
                if ( $sawHeader ) {
                    return false;
                }
                $sawHeader = true;
                $acl['inherited'] = !empty( $header[1] );
                $section = '';
                continue;
            }
            if ( preg_match( '/^Volume access list for .+ is$/i', $line )) {
                // A Volume Maximum ACL is a separate, read-only policy block.
                // Never merge it into the editable object ACL.
                return false;
            }
            if ( preg_match( '/^Normal rights:$/i', $line )) {
                if ( !$sawHeader || $sawNormal ) {
                    return false;
                }
                $section = 'normal';
                $sawNormal = true;
                continue;
            }
            if ( preg_match( '/^Negative rights:$/i', $line )) {
                if ( !$sawNormal || $sawNegative ) {
                    return false;
                }
                $section = 'negative';
                $sawNegative = true;
                continue;
            }
            if ( !$section || !preg_match( '/^(\S+)\s+(\S+)$/', $line, $matches )) {
                return false;
            }
            if ( $matches[2] !== 'none'
              && !preg_match( '/^[lrwidkaA-H]{1,15}$/', $matches[2] )) {
                return false;
            }

            $seenRights = array();
            foreach ( str_split( $matches[2] ) as $setRight ) {
                if ( isset( $seenRights[$setRight] )) {
                    return false;
                }
                $seenRights[$setRight] = true;
            }

            foreach ( $rights as $right ) {
                $acl[$section][$matches[1]][$right] =
                    strpos( $matches[2], $right ) !== false;
            }
        }

        if ( !$sawHeader || !$sawNormal ) {
            return false;
        }

        return $acl;
    }

    function getACLAccess( $path )
    {
        $this->lookupPriv = 0;
        $this->readPriv = 0;
        $this->writePriv = 0;
        $this->insertPriv = 0;
        $this->deletePriv = 0;
        $this->lockPriv = 0;
        $this->adminPriv = 0;

        $path = $this->pathSecurity( $path );
        if ( !$path ) {
            return '';
        }

        $result = $this->runFs( array( 'getcalleraccess', $path ));
        if ( $result === false || $this->lastFsStatus !== 0 ) {
            return '';
        }

        $acls = '';
        if ( preg_match( '/^Callers access to .* is ([lrwidkaA-H]{1,15})$/m',
                $result, $Matches )) {
            $acls = $Matches[1];
            $this->lookupPriv = strpos( $acls, 'l' ) !== false ? 1 : 0;
            $this->readPriv   = strpos( $acls, 'r' ) !== false ? 1 : 0;
            $this->writePriv  = strpos( $acls, 'w' ) !== false ? 1 : 0;
            $this->insertPriv = strpos( $acls, 'i' ) !== false ? 1 : 0;
            $this->deletePriv = strpos( $acls, 'd' ) !== false ? 1 : 0;
            $this->lockPriv   = strpos( $acls, 'k' ) !== false ? 1 : 0;
            $this->adminPriv  = strpos( $acls, 'a' ) !== false ? 1 : 0;
        }
        return $acls;
    }

    protected function runFs( $arguments )
    {
        if ( !is_array( $arguments ) || empty( $arguments )) {
            return false;
        }

        $command = 'LC_ALL=C ' . escapeshellarg( $this->afsUtils . '/fs' );
        foreach ( $arguments as $argument ) {
            $command .= ' ' . escapeshellarg( $argument );
        }

        if ( !function_exists( 'exec' )) {
            $this->lastFsStatus = 126;
            return false;
        }

        $output = array();
        $status = 0;
        exec( $command . ' 2>&1', $output, $status );
        $this->lastFsStatus = $status;
        return implode( "\n", $output );
    }

    /*
     * List the contents of a folder as a set of javascript
     * variable declarations.
     *
     */
    public function get_foldercontents_js( $showHidden=false )
    {
        $id = 0;
        $files = '';

        if ( is_file( $this->path )) {
            $path = dirname( $this->path );
        } else {
            $path = $this->path;
        }

        if ( !$this->makePathAFSlocal( $path )) {
            $this->errorMsg = "Unable to view: $this->path.";
            return false;
        }

        if ( !@is_dir( '.' )) {
            @chdir( $this->startCWD );
            return false;
        }

        // Open the path and read its contents
        if ( !$dh = @opendir( '.' )) {
            $this->errorMsg = "Unable to view: $this->path.";
            @chdir( $this->startCWD );
            return false;
        }

        while ( $filename = readdir( $dh )) {
            clearstatcache();
            if ( !$fileStats = @lstat( $filename )) {
                $modTime = '';
                $size = 0;
            } else {
                $modTime = $fileStats['mtime'];
                $size = $fileStats['size'];
            }

            //$mimeType = Mime::getMimeType( $filename );
            //$mimeIcon = Mime::getIcon( $mimeType, $filename );
            $filename = $this->escape_js( $filename );

            $viewable = 0;

            //if ( Mime::getPreviewType( $mimeType ) || @is_dir( $filename )) {
                //$viewable = 1;
            //}

            if ( $showHidden || strpos( $filename, '.' ) !== 0 ) {
                $files .= "files[$id]=new File('$filename', '$modTime', $size, "
                  . "'', '$mimeIcon', $viewable);\n";
            }

            $id++;
        }

        closedir( $dh );
        @chdir( $this->startCWD );
        return $files;
    }

    function get_foldername()
    {
        return basename( $this->path );
    }

    function get_returnToURI()
    {
        if ( !defined( 'FM_SELF_URL' )) {
            return '';
        }
        return ( FM_SELF_URL .
                 "?path=" .
                 urlencode($this->path) .
                 "&" .
                 "finishid=" .
                 $this->sid );
    }

    /*
    * Return a string escaped for a javascript string literal.
    */
    function escape_js( $string )
    {
        $output = "";

        $length = strlen( $string );
        for( $i=0; $i<$length; $i++ )
        {
            $c = $string[$i];
            switch( $c )
            {
                case '\'':
                    $output .= '\\\'';
                    break;
                case '\\':
                    $output .= '\\\\';
                    break;
                case "\n":
                    $output .= '\\n';
                    break;
                case "\r":
                    $output .= '\\r';
                    break;
                default:
                    $output .= $c;
                    break;
            }
        }

        return $output;
    }

    /* An initial check to make sure the path is in AFS.  This is an initial
     * check only.  To avoid race conditions, other precaustions must be used.
     * CAUTION: This method will be removed in the next major release.
     */
    protected function pathSecurity( $path='' )
    {
        if ( !$this->afsAvailable || empty( $path )
          || !is_array( $this->afsStat )) {
            return false;
        }

        /* The path is only safe if we're in AFS at the end of it.
         * This test is raceable - so we should check again before sending
         * anything to the client.
         */
        clearstatcache();

        if ( !$pathStat = @stat( $path )) {
            return false;
        }

        if ( $this->afsStat["dev"] !=  $pathStat["dev"] ) {
            return false;
        }

        // Remove the final / in the target path if it exists
        return rtrim( $path, '/' );
    }


    public function makePathAFSlocal( $path )
    {
        if ( !$this->afsAvailable || !is_array( $this->afsStat )) {
            $this->errorMsg = 'AFS is not mounted.';
            return false;
        }

        if ( !@chdir( $path )) {
            $this->errorMsg = "Couldn't change directory";
            return false;
        }

        clearstatcache();
        $stat = @stat( '.' );
        if ( !is_array( $stat ) || $this->afsStat['dev'] != $stat['dev'] ) {
            $this->errorMsg = "Path not in AFS";
            @chdir( $this->startCWD );
            return false;
        }

        return true;
    }


    // Checks to see if there is a folder at the current path
    function folderExists( $path='' )
    {
        $path = ( $path ) ? $path : $this->path;
        return is_dir( $path );
    }


    public function linkSafeFileExists( $path )
    {
        clearstatcache();

        if ( is_array( @lstat( $path ))) {
            return true;
        } else {
            return false;
        }
    }


    // Set the afs path used inside the class
    function setPath( $path='' )
    {
        $safePath = $this->pathSecurity( $path );
        if ( !$safePath ) {
            $this->path = '';
            $this->errorMsg = 'Path not in AFS';
            return false;
        }

        $this->path = $safePath;
        return true;
    }

    public function isAvailable()
    {
        return $this->afsAvailable;
    }

    // Makes each piece of a file path clickable
    function pathDisplay()
    {
        if ( empty( $this->path )) {
            return '';
        }

        $path     = preg_replace( '/^\/afs\//', '', $this->path );
        $path     = explode( '/', $path );
        $lastItem = array_pop( $path );
        $pathDisp = '/afs';
        $pathURI  = '/afs';
        $lastDisp = '';
        $lastURI  = '';

        foreach ( $path as $piece ) {
            $pathURI  .= "/$piece";
            $pathDisp .= "/<a href=\"/?path=" . rawurlencode( $pathURI ) . "\">"
                    . htmlentities( $piece ) . "</a>";
        }

        $pathURI  .= $lastURI;
        $pathDisp .= $lastDisp;

        return $pathDisp . '/' . htmlentities( $lastItem );
    }

    // Make smarty template variable assignments
    function make_smarty_assignments(&$smart)
    {
        $smart->assign( 'path_url', urlencode($this->path));
        $smart->assign( 'parentPath', urlencode($this->parPath ));
        $smart->assign( 'location', $this->pathDisplay());
    }

    function get_js_declarations()
    {
        $retstr = "";

        $retstr .= $this->js_var( "path", $this->path );
        $retstr .= $this->js_var( "foldername", $this->get_foldername( ));
        $retstr .= $this->js_var( "folderIcon", "" );
        $retstr .= $this->js_var( "homepath", $this->path );
        $retstr .= $this->js_var( "sid", $this->sid );
        $retstr .= $this->js_var( "returnToURI", $this->get_returnToURI( ));
        $retstr .= $this->js_var( "adminPriv", $this->adminPriv);
        $retstr .= $this->js_var( "deletePriv", $this->deletePriv);
        $retstr .= $this->js_var( "insertPriv", $this->insertPriv );
        $retstr .= $this->js_var( "lockPriv", $this->lockPriv );
        $retstr .= $this->js_var( "readPriv", $this->readPriv );
        $retstr .= $this->js_var( "lookupPriv", $this->lookupPriv );
        $retstr .= $this->js_var( "writePriv", $this->writePriv );
        $retstr .= "files = new Array();\n";
        $retstr .= $this->get_foldercontents_js( true );

        return $retstr;
    }

    private function js_var( $varname, $contents )
    {
        $retstr = "";
        $retstr .= "var $varname = " .
            ( is_string( $contents ) ?
                "'" . $this->escape_js( $contents ) . "'"
                : $contents )
            . ";\n";
        return $retstr;
    }

}

class AfsProductionReadiness
{
    const PRODUCTION_PROFILE = 'afs-descriptor-v1';

    const LOCAL_ONLY_CONTENT_SECURITY_POLICY = "default-src 'none'; " .
        "base-uri 'none'; connect-src 'self'; font-src 'self'; " .
        "form-action 'self'; frame-ancestors 'none'; frame-src 'none'; " .
        "img-src 'self' data:; media-src 'self'; object-src 'none'; " .
        "script-src 'self'; style-src 'self'; worker-src 'self'";

    public static function validateProductionProfile( $state, &$error=null )
    {
        $keys = array(
            'profile', 'afs_enabled', 'external_auth', 'request_identity',
            'local_auth', 'local_users_empty', 'settings_enabled',
            'embed_enabled', 'direct_links_enabled',
            'raw_previews_enabled', 'url_upload_enabled',
            'root_url', 'self_url',
            'data_root', 'asset_manifest_sha256',
            'expected_factory_class', 'expected_factory_id',
            'expected_provider_class', 'expected_provider_id'
        );
        if ( !is_array( $state ) || count( $state ) !== count( $keys )
          || array_diff_key( array_flip( $keys ), $state )
          || array_diff_key( $state, array_flip( $keys ))) {
            $error = 'The AFS production profile is missing or malformed.';
            return false;
        }

        $fixed = array(
            'profile' => self::PRODUCTION_PROFILE,
            'afs_enabled' => true,
            'external_auth' => true,
            'local_auth' => false,
            'local_users_empty' => true,
            'settings_enabled' => false,
            'embed_enabled' => false,
            'direct_links_enabled' => false,
            'raw_previews_enabled' => false,
            'url_upload_enabled' => false,
            'root_url' => ''
        );
        foreach ( $fixed as $key => $expected ) {
            if ( $state[$key] !== $expected ) {
                $error = 'Invalid AFS production profile setting: ' . $key;
                return false;
            }
        }

        if ( !is_string( $state['request_identity'] )
          || $state['request_identity'] === ''
          || trim( $state['request_identity'] ) !== $state['request_identity']
          || preg_match( '/[\x00-\x1f\x7f]/', $state['request_identity'] )) {
            $error = 'AFS production requires a trusted external identity.';
            return false;
        }
        if ( !is_string( $state['self_url'] )
          || $state['self_url'] === ''
          || substr( $state['self_url'], 0, 1 ) !== '/'
          || strpos( $state['self_url'], '//' ) !== false
          || preg_match( '/[\x00\r\n?#]/', $state['self_url'] )) {
            $error = 'AFS production requires a root-relative controller URL.';
            return false;
        }
        if ( !is_string( $state['data_root'] )
          || strpos( $state['data_root'], '/afs/' ) !== 0
          || rtrim( $state['data_root'], '/' ) !== $state['data_root']
          || strpos( $state['data_root'], '\\' ) !== false
          || preg_match( '/[\x00-\x1f\x7f]/', $state['data_root'] )) {
            $error = 'AFS production requires one absolute data root below /afs.';
            return false;
        }
        foreach ( explode( '/', substr( $state['data_root'], 5 ))
                as $segment ) {
            if ( $segment === '' || $segment === '.' || $segment === '..' ) {
                $error = 'The AFS production data root is not normalized.';
                return false;
            }
        }
        if ( !is_string( $state['asset_manifest_sha256'] )
          || !preg_match( '/^[a-f0-9]{64}$/',
                $state['asset_manifest_sha256'] )) {
            $error = 'AFS production requires a lowercase manifest SHA-256.';
            return false;
        }
        foreach ( array(
                'expected_factory_class', 'expected_factory_id',
                'expected_provider_class', 'expected_provider_id'
            ) as $key ) {
            if ( !is_string( $state[$key] ) || $state[$key] === ''
              || strlen( $state[$key] ) > 255
              || !preg_match( '/^[A-Za-z0-9_.:@+\\\\\/-]+$/',
                    $state[$key] )) {
                $error = 'Invalid AFS production identity setting: ' . $key;
                return false;
            }
        }
        return true;
    }

    public static function applicationTemplatesSupportStrictCsp()
    {
        // Tiny File Manager 2.6 still emits inline script/style blocks and
        // event-handler attributes. AFS production must remain unavailable
        // until those templates use reviewed external assets plus nonces or
        // hashes; accepting unsafe-inline/unsafe-eval is not an alternative.
        return false;
    }

    public static function validateContentSecurityPolicy( $policy, &$error=null )
    {
        if ( !is_string( $policy ) || trim( $policy ) === '' ) {
            $error = 'AFS production mode requires a reviewed ' .
                'Content-Security-Policy.';
            return false;
        }
        if ( preg_match( '/[\x00\r\n]/', $policy )) {
            $error = 'Invalid Content-Security-Policy configuration.';
            return false;
        }
        if ( $policy !== self::LOCAL_ONLY_CONTENT_SECURITY_POLICY ) {
            $error = 'The AFS CSP must match the canonical 13-directive ' .
                'application policy exactly.';
            return false;
        }

        $required = array(
            'default-src', 'base-uri', 'connect-src', 'font-src',
            'form-action', 'frame-ancestors', 'frame-src', 'img-src',
            'media-src', 'object-src', 'script-src', 'style-src',
            'worker-src'
        );
        $directives = array();
        foreach ( explode( ';', $policy ) as $clause ) {
            $clause = trim( $clause );
            if ( $clause === '' ) {
                continue;
            }
            $parts = preg_split( '/\s+/', $clause );
            $name = strtolower( array_shift( $parts ));
            if ( !preg_match( '/^[a-z][a-z0-9-]*$/', $name )
              || isset( $directives[$name] )) {
                $error = 'The CSP contains an invalid or duplicate directive.';
                return false;
            }
            if ( !in_array( $name, $required, true )) {
                $error = 'The CSP contains an unreviewed directive: ' . $name;
                return false;
            }
            $directives[$name] = $parts;
        }

        foreach ( $required as $name ) {
            if ( !isset( $directives[$name] )
              || empty( $directives[$name] )) {
                $error = 'The CSP is missing required directive ' . $name . '.';
                return false;
            }
            if ( !self::validateLocalCspSources(
                    $name, $directives[$name], $error )) {
                return false;
            }
        }
        return true;
    }

    protected static function validateLocalCspSources( $name, $sources,
                                                        &$error )
    {
        if ( empty( $sources )) {
            $error = $name . ' must contain at least one CSP source.';
            return false;
        }
        if (( $name === 'object-src' || $name === 'frame-src' )
          && $sources !== array( "'none'" )) {
            $error = $name . " must be exactly 'none' in AFS mode.";
            return false;
        }
        if ( in_array( "'none'", $sources, true ) && count( $sources ) !== 1 ) {
            $error = "'none' cannot be combined with other CSP sources.";
            return false;
        }

        foreach ( $sources as $source ) {
            if ( $source === "'self'" || $source === "'none'" ) {
                continue;
            }
            if ( $source === 'data:'
              && ( $name === 'img-src' || $name === 'font-src' )) {
                continue;
            }
            if ( preg_match( "/^'(?:nonce-[A-Za-z0-9+\/_-]+=*|sha(?:256|384|512)-[A-Za-z0-9+\/=]+)'$/",
                    $source )
              && ( $name === 'script-src' || $name === 'style-src' )) {
                continue;
            }
            $error = 'Remote, wildcard, or unsupported CSP source in ' .
                $name . ': ' . $source;
            return false;
        }

        if ( in_array( $name, array(
                'default-src', 'script-src', 'style-src', 'img-src',
                'font-src', 'connect-src', 'media-src', 'base-uri',
                'form-action', 'worker-src' ), true )
          && !in_array( "'self'", $sources, true )
          && !in_array( "'none'", $sources, true )) {
            $error = $name . " must contain 'self' or 'none'.";
            return false;
        }
        return true;
    }

    public static function buildLocalAssetTags( $manifest, $assetRoot,
                                                 &$error=null )
    {
        $types = array(
            'css-bootstrap' => 'style',
            'css-dropzone' => 'style',
            'css-font-awesome' => 'style',
            'css-highlightjs' => 'style',
            'js-ace' => 'script',
            'js-bootstrap' => 'script',
            'js-dropzone' => 'script',
            'js-jquery' => 'script',
            'js-jquery-datatables' => 'script',
            'js-highlightjs' => 'script'
        );
        if ( !is_array( $manifest )
          || count( $manifest ) !== count( $types )
          || array_diff_key( $manifest, $types )
          || array_diff_key( $types, $manifest )) {
            $error = 'The AFS local asset manifest must contain exactly the ' .
                'required script and style keys.';
            return false;
        }

        $tags = array();
        foreach ( $types as $key => $expectedType ) {
            $entry = $manifest[$key];
            if ( !is_array( $entry )) {
                $error = 'Invalid asset manifest row for ' . $key . '.';
                return false;
            }
            $allowedFields = array(
                'type' => true, 'path' => true, 'sha256' => true,
                'license' => true, 'defer' => true
            );
            if ( array_diff_key( $entry, $allowedFields )
              || !isset( $entry['type'], $entry['path'], $entry['sha256'],
                    $entry['license'], $entry['defer'] )
              || $entry['type'] !== $expectedType
              || !is_bool( $entry['defer'] )
              || ( $expectedType === 'style' && $entry['defer'] !== false )) {
                $error = 'Invalid typed asset fields for ' . $key . '.';
                return false;
            }
            if ( !in_array( $entry['license'], array(
                    'MIT', 'BSD-3-Clause', 'Apache-2.0', 'OFL-1.1'
                ), true )) {
                $error = 'Unreviewed asset license for ' . $key . '.';
                return false;
            }
            if ( !self::validateLocalAsset(
                    $entry['path'], $assetRoot, $entry['sha256'], $error )) {
                return false;
            }

            $url = htmlspecialchars(
                $entry['path'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
            if ( $expectedType === 'style' ) {
                $tags[$key] = '<link rel="stylesheet" href="' . $url . '">';
            } else {
                $defer = !empty( $entry['defer'] ) ? ' defer' : '';
                $tags[$key] = '<script src="' . $url . '"' .
                    $defer . '></script>';
            }
        }
        $tags['pre-jsdelivr'] = '';
        $tags['pre-cloudflare'] = '';
        return $tags;
    }

    public static function buildLocalAssetTagsFromManifestFile(
        $manifestFile, $assetRoot, $manifestSha256, &$error=null )
    {
        if ( !is_string( $manifestFile ) || $manifestFile === ''
          || trim( $manifestFile ) !== $manifestFile
          || substr( $manifestFile, 0, 1 ) === '/'
          || strpos( $manifestFile, '%' ) !== false
          || strpos( $manifestFile, '?' ) !== false
          || strpos( $manifestFile, '#' ) !== false
          || strpos( $manifestFile, '\\' ) !== false
          || preg_match( '/[\x00-\x20\x7f]/', $manifestFile )) {
            $error = 'Invalid AFS asset-manifest path.';
            return false;
        }
        foreach ( explode( '/', $manifestFile ) as $segment ) {
            if ( $segment === '' || $segment === '.' || $segment === '..' ) {
                $error = 'Invalid AFS asset-manifest path component.';
                return false;
            }
        }

        $root = is_string( $assetRoot ) ? @realpath( $assetRoot ) : false;
        if ( $root === false ) {
            $error = 'The AFS asset root is unavailable.';
            return false;
        }
        $candidate = $root;
        foreach ( explode( '/', $manifestFile ) as $segment ) {
            $candidate .= '/' . $segment;
            $component = @lstat( $candidate );
            if ( !is_array( $component )
              || ( isset( $component['mode'] )
                && ( $component['mode'] & 0170000 ) === 0120000 )) {
                $error = 'The AFS asset manifest cannot contain symlinks.';
                return false;
            }
        }
        $resolved = @realpath( $candidate );
        $root = rtrim( str_replace( '\\', '/', $root ), '/' );
        $resolved = $resolved === false ? false
            : str_replace( '\\', '/', $resolved );
        if ( $resolved === false
          || strpos( $resolved, $root . '/' ) !== 0
          || !is_file( $resolved ) || !is_readable( $resolved )) {
            $error = 'The AFS asset manifest is unavailable or outside its root.';
            return false;
        }
        $raw = @file_get_contents( $resolved );
        if ( !is_string( $raw ) || strlen( $raw ) > 1048576 ) {
            $error = 'Unable to read the AFS asset manifest.';
            return false;
        }
        if ( !is_string( $manifestSha256 )
          || !preg_match( '/^[a-f0-9]{64}$/', $manifestSha256 )
          || !hash_equals( $manifestSha256, hash( 'sha256', $raw ))) {
            $error = 'AFS asset-manifest digest mismatch.';
            return false;
        }
        $decoded = json_decode( $raw, true );
        if ( !is_array( $decoded )
          || count( $decoded ) !== 2
          || !array_key_exists( 'version', $decoded )
          || !array_key_exists( 'assets', $decoded )
          || $decoded['version'] !== 1
          || !is_array( $decoded['assets'] )) {
            $error = 'Invalid AFS asset-manifest schema.';
            return false;
        }
        return self::buildLocalAssetTags(
            $decoded['assets'], $root, $error );
    }

    public static function validateLocalAsset( $reference, $assetRoot,
                                                $sha256, &$error=null )
    {
        if ( !is_string( $reference ) || trim( $reference ) !== $reference
          || $reference === '' || substr( $reference, 0, 1 ) === '/'
          || strpos( $reference, '%' ) !== false
          || strpos( $reference, '?' ) !== false
          || strpos( $reference, '#' ) !== false
          || strpos( $reference, '\\' ) !== false
          || preg_match( '/[\x00-\x20\x7f]/', $reference )
          || preg_match( '/^[a-z][a-z0-9+.-]*:/i', $reference )) {
            $error = 'Invalid local asset path.';
            return false;
        }
        foreach ( explode( '/', $reference ) as $segment ) {
            if ( $segment === '' || $segment === '.' || $segment === '..' ) {
                $error = 'Invalid local asset path component.';
                return false;
            }
        }
        if ( !is_string( $sha256 )
          || !preg_match( '/^[a-f0-9]{64}$/', $sha256 )) {
            $error = 'Each local asset requires a reviewed SHA-256 digest.';
            return false;
        }

        $root = is_string( $assetRoot ) ? @realpath( $assetRoot ) : false;
        $candidatePath = $root !== false ? $root : '';
        if ( $root !== false ) {
            foreach ( explode( '/', $reference ) as $segment ) {
                $candidatePath .= '/' . $segment;
                $component = @lstat( $candidatePath );
                if ( !is_array( $component )
                  || ( isset( $component['mode'] )
                    && ( $component['mode'] & 0170000 ) === 0120000 )) {
                    $error = 'Local asset paths cannot contain symbolic links: ' .
                        $reference;
                    return false;
                }
            }
        }
        $candidate = $root !== false ? @realpath( $candidatePath ) : false;
        if ( $root === false || $candidate === false ) {
            $error = 'Required local asset is missing: ' . $reference;
            return false;
        }
        $root = rtrim( str_replace( '\\', '/', $root ), '/' );
        $candidate = str_replace( '\\', '/', $candidate );
        $withinRoot = $candidate === $root
            || ( $root === ''
                ? strpos( $candidate, '/' ) === 0
                : strpos( $candidate, $root . '/' ) === 0 );
        if ( !$withinRoot || !is_file( $candidate )
          || !is_readable( $candidate )) {
            $error = 'Local asset is unavailable or outside the configured ' .
                'asset root: ' . $reference;
            return false;
        }
        $actual = @hash_file( 'sha256', $candidate );
        if ( !is_string( $actual )
          || !hash_equals( $sha256, $actual )) {
            $error = 'Local asset digest mismatch: ' . $reference;
            return false;
        }
        return true;
    }

}

/*
 * Path-policy preview for the Tiny File Manager data-plane provider API.
 *
 * The historical Afs helpers above only prove that an object is on the same
 * client device as /afs.  They do not constrain an operation to the configured
 * Tiny File Manager root.  This facade owns both resolution and I/O so an AFS
 * failure can never fall through to a generic filesystem helper.  It is not a
 * production security boundary: PHP 7.4 cannot bind a pathname walk and later
 * mutation to one directory descriptor.  A production implementation must use
 * an openat2-style RESOLVE_BENEATH/RESOLVE_NO_MAGICLINKS boundary (initially
 * RESOLVE_NO_SYMLINKS), or an equivalent native broker.
 *
 * POSIX symbolic links and kernel mount points below the configured root are
 * rejected.  AFS volume mount points are different objects: ordinary logical
 * traversal through them is allowed, but recursive copy/delete stops at a
 * child volume boundary.  A user can navigate into that volume and start a new
 * operation there.  The exact mutation semantics still require live YFS tests.
 */
class AfsDataPlane extends Afs implements AfsDataPlaneProvider
{
    protected $dataRoot = '';
    protected $dataRootDevice = null;
    protected $dataRootIdentity = array();
    protected $kernelMountPoints = null;
    protected $volumeMountCache = array();
    protected $identityCache = array();
    protected $crossedVolumeMounts = array();

    public function isProductionReady()
    {
        return false;
    }

    public function getReadinessFailure()
    {
        return 'The bundled PHP AFS provider is pathname-based. Configure a ' .
            'descriptor-backed AfsDataPlaneProvider before production use.';
    }

    public function getSecurityBoundary()
    {
        return 'pathname-preview';
    }

    public function getProviderIdentity()
    {
        return 'tinyfilemanager-afs-pathname-preview-v1';
    }

    public function getCredentialIdentity()
    {
        return $this->credentialIdentity;
    }

    public function initializeDataPlane( $root )
    {
        if ( !$this->isAvailable() || !is_array( $this->afsStat )) {
            $this->errorMsg = 'AFS data-plane guard is unavailable.';
            return false;
        }

        $root = $this->normalizeAbsolutePath( $root );
        if ( $root === false ) {
            $this->errorMsg = 'Invalid AFS data root.';
            return false;
        }

        $rootLstat = $this->pathLstat( $root );
        $rootStat = $this->pathStat( $root );
        $rootReal = $this->pathRealpath( $root );
        if ( !is_array( $rootLstat ) || !is_array( $rootStat )
          || $this->statIsLink( $rootLstat )
          || !$this->statIsDirectory( $rootStat )
          || $rootReal === false ) {
            $this->errorMsg = 'The configured root is not a real AFS directory.';
            return false;
        }

        $rootReal = $this->normalizeAbsolutePath( $rootReal );
        if ( $rootReal === false ) {
            $this->errorMsg = 'Unable to resolve the configured AFS root.';
            return false;
        }

        $mounts = $this->loadKernelMountPoints();
        if ( !is_array( $mounts )) {
            $this->errorMsg = 'Unable to inspect the kernel mount table.';
            return false;
        }

        $this->dataRoot = $rootReal;
        $this->dataRootDevice = $rootStat['dev'];
        $this->kernelMountPoints = array_fill_keys( $mounts, true );

        $identity = $this->probeAfsIdentity( $rootReal, false, true );
        if ( !is_array( $identity )) {
            $this->dataRoot = '';
            $this->errorMsg = 'Unable to identify the configured AFS root.';
            return false;
        }

        $this->dataRootIdentity = $identity;
        return true;
    }

    public function getDataRoot()
    {
        return $this->dataRoot;
    }

    public function getCrossedVolumeMounts()
    {
        return $this->crossedVolumeMounts;
    }

    public function archivesSupported()
    {
        // ZipArchive::extractTo(), PharData::extractTo(), and the upstream
        // archive walkers own their own pathname traversal.  They must not be
        // used in AFS mode until per-entry guarded implementations exist.
        return false;
    }

    public function resolveExistingPath( $path, $type='any' )
    {
        return $this->resolveConfinedPath( $path, $type, false );
    }

    public function resolveWritePath( $path, $allowExisting=true )
    {
        $path = $this->normalizeAbsolutePath( $path );
        if ( $path === false || !$this->pathWithinRoot( $path )
          || $path === $this->dataRoot ) {
            $this->errorMsg = 'Write target is outside the configured AFS root.';
            return false;
        }

        $existing = $this->pathLstat( $path );
        if ( is_array( $existing )) {
            if ( !$allowExisting ) {
                $this->errorMsg = 'The destination already exists.';
                return false;
            }
            return $this->resolveConfinedPath( $path, 'file', false );
        }

        $leaf = basename( $path );
        if ( !$this->validLeafName( $leaf )) {
            $this->errorMsg = 'Invalid AFS destination name.';
            return false;
        }

        $parent = $this->resolveConfinedPath( dirname( $path ), 'dir', false );
        if ( $parent === false ) {
            return false;
        }

        return $parent . '/' . $leaf;
    }

    public function inspectPath( $path, $allowLinkObject=false )
    {
        $path = $allowLinkObject
            ? $this->resolveObjectPath( $path )
            : $this->resolveExistingPath( $path );
        if ( $path === false ) {
            return false;
        }

        $lstat = $this->pathLstat( $path );
        if ( !is_array( $lstat )) {
            return false;
        }
        if ( $this->statIsLink( $lstat )) {
            if ( !$allowLinkObject ) {
                return false;
            }
            $target = @readlink( $path );
            if ( $target === false ) {
                return false;
            }
            return array(
                'path' => $path,
                'type' => 'link',
                'size' => isset( $lstat['size'] ) ? $lstat['size'] : 0,
                'mtime' => isset( $lstat['mtime'] ) ? $lstat['mtime'] : 0,
                'mode' => isset( $lstat['mode'] ) ? $lstat['mode'] : 0,
                'link_target' => $target
            );
        }

        $stat = $this->pathStat( $path );
        if ( !is_array( $stat )) {
            return false;
        }
        if ( $this->statIsDirectory( $stat )) {
            $type = 'dir';
        } elseif ( $this->statIsFile( $stat )) {
            $type = 'file';
        } else {
            return false;
        }
        return array(
            'path' => $path,
            'type' => $type,
            'size' => isset( $stat['size'] ) ? $stat['size'] : 0,
            'mtime' => isset( $stat['mtime'] ) ? $stat['mtime'] : 0,
            'mode' => isset( $stat['mode'] ) ? $stat['mode'] : 0,
            'link_target' => false
        );
    }

    public function listDirectory( $path )
    {
        $path = $this->resolveExistingPath( $path, 'dir' );
        if ( $path === false ) {
            return false;
        }

        $items = @scandir( $path );
        if ( !is_array( $items )) {
            $this->errorMsg = 'Unable to list the AFS directory.';
            return false;
        }

        $safe = array();
        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) {
                continue;
            }
            if ( $this->inspectPath(
                    $path . '/' . $item, true ) !== false ) {
                $safe[] = $item;
            }
        }
        return $safe;
    }

    public function searchFiles( $path, $filter='' )
    {
        $path = $this->resolveExistingPath( $path, 'dir' );
        if ( $path === false ) {
            return false;
        }

        $results = array();
        if ( !$this->searchDirectory( $path, $path, (string)$filter, $results )) {
            return false;
        }
        return $results;
    }

    public function openRead( $path )
    {
        $path = $this->resolveExistingPath( $path, 'file' );
        if ( $path === false ) {
            return false;
        }

        $handle = @fopen( $path, 'rb' );
        if ( $handle === false || !$this->validateOpenHandle( $handle, $path )) {
            if ( is_resource( $handle )) {
                @fclose( $handle );
            }
            $this->errorMsg = 'Unable to open a confined AFS file.';
            return false;
        }

        return $handle;
    }

    public function readContents( $path )
    {
        $handle = $this->openRead( $path );
        if ( $handle === false ) {
            return false;
        }

        $contents = '';
        $ok = true;
        while ( !feof( $handle )) {
            $buffer = fread( $handle, 1024 * 1024 );
            if ( $buffer === false ) {
                $ok = false;
                break;
            }
            $contents .= $buffer;
        }
        if ( !@fclose( $handle )) {
            $ok = false;
        }

        if ( !$ok ) {
            $this->errorMsg = 'Unable to read the complete AFS file.';
            return false;
        }
        return $contents;
    }

    public function detectMimeType( $path )
    {
        $handle = $this->openRead( $path );
        if ( $handle === false ) {
            return false;
        }
        $sample = @fread( $handle, 262144 );
        $closed = @fclose( $handle );
        if ( $sample === false || !$closed ) {
            $this->errorMsg = 'Unable to sample the confined AFS file.';
            return false;
        }

        if ( function_exists( 'finfo_open' )
          && function_exists( 'finfo_buffer' )) {
            $finfo = @finfo_open( FILEINFO_MIME_TYPE );
            if ( $finfo !== false ) {
                $mime = @finfo_buffer( $finfo, $sample );
                if ( PHP_VERSION_ID < 80000 ) {
                    @finfo_close( $finfo );
                }
                if ( is_string( $mime ) && $mime !== '' ) {
                    return $mime;
                }
            }
        }
        return 'application/octet-stream';
    }

    public function readAcl( $path='' )
    {
        $path = $this->resolveExistingPath( $path );
        return $path !== false ? parent::readAcl( $path ) : false;
    }

    public function changeAclEntries( $entries, $path='', $negative=false )
    {
        $path = $this->resolveExistingPath( $path );
        return $path !== false
            ? parent::changeAclEntries( $entries, $path, $negative ) : false;
    }

    public function getACLAccess( $path )
    {
        $path = $this->resolveExistingPath( $path );
        return $path !== false ? parent::getACLAccess( $path ) : '';
    }

    public function createFile( $path )
    {
        $path = $this->resolveWritePath( $path, false );
        if ( $path === false ) {
            return false;
        }

        $handle = @fopen( $path, 'x+b' );
        if ( $handle === false || !$this->validateOpenHandle( $handle, $path )) {
            if ( is_resource( $handle )) {
                @fclose( $handle );
            }
            @unlink( $path );
            $this->errorMsg = 'Unable to create a confined AFS file.';
            return false;
        }

        $ok = @fflush( $handle );
        if ( !@fclose( $handle )) {
            $ok = false;
        }
        if ( !$ok ) {
            @unlink( $path );
            $this->errorMsg = 'Unable to close the new AFS file.';
            return false;
        }
        return $this->resolveExistingPath( $path, 'file' ) !== false;
    }

    public function writeFile( $path, $contents )
    {
        $path = $this->resolveWritePath( $path, true );
        if ( $path === false ) {
            return false;
        }

        $newFile = !is_array( $this->pathLstat( $path ));
        $handle = @fopen( $path, $newFile ? 'x+b' : 'c+b' );
        if ( $handle === false || !$this->validateOpenHandle( $handle, $path )) {
            if ( is_resource( $handle )) {
                @fclose( $handle );
            }
            if ( $newFile ) {
                @unlink( $path );
            }
            $this->errorMsg = 'Unable to open the AFS write target.';
            return false;
        }

        $ok = @ftruncate( $handle, 0 ) && @rewind( $handle );
        if ( $ok ) {
            $ok = $this->writeAll( $handle, (string)$contents );
        }
        if ( $ok ) {
            $ok = @fflush( $handle );
        }
        if ( !@fclose( $handle )) {
            $ok = false;
        }

        if ( !$ok ) {
            if ( $newFile ) {
                @unlink( $path );
            }
            $this->errorMsg = 'Unable to write the complete AFS file.';
            return false;
        }
        return $this->resolveExistingPath( $path, 'file' ) !== false;
    }

    public function importFile( $source, $destination, $overwrite=true,
                                $append=false )
    {
        $sourceHandle = @fopen( $source, 'rb' );
        $sourceStat = is_resource( $sourceHandle ) ? @fstat( $sourceHandle ) : false;
        if ( $sourceHandle === false || !is_array( $sourceStat )
          || !$this->statIsFile( $sourceStat )) {
            if ( is_resource( $sourceHandle )) {
                @fclose( $sourceHandle );
            }
            $this->errorMsg = 'Unable to open the import source.';
            return false;
        }

        $destination = $this->resolveWritePath( $destination, $overwrite );
        if ( $destination === false ) {
            @fclose( $sourceHandle );
            return false;
        }

        $newFile = !is_array( $this->pathLstat( $destination ));
        $destinationHandle = @fopen(
            $destination, $newFile ? 'x+b' : 'c+b' );
        if ( $destinationHandle === false
          || !$this->validateOpenHandle( $destinationHandle, $destination )) {
            @fclose( $sourceHandle );
            if ( is_resource( $destinationHandle )) {
                @fclose( $destinationHandle );
            }
            if ( $newFile ) {
                @unlink( $destination );
            }
            $this->errorMsg = 'Unable to open the AFS import target.';
            return false;
        }

        $ok = true;
        if ( $append ) {
            $ok = @fseek( $destinationHandle, 0, SEEK_END ) === 0;
        } else {
            $ok = @ftruncate( $destinationHandle, 0 )
                && @rewind( $destinationHandle );
        }

        while ( $ok && !feof( $sourceHandle )) {
            $buffer = fread( $sourceHandle, 1024 * 1024 );
            if ( $buffer === false ) {
                $ok = false;
                break;
            }
            if ( !$this->writeAll( $destinationHandle, $buffer )) {
                $ok = false;
            }
        }
        if ( $ok ) {
            $ok = @fflush( $destinationHandle );
        }
        if ( !@fclose( $sourceHandle )) {
            $ok = false;
        }
        if ( !@fclose( $destinationHandle )) {
            $ok = false;
        }

        if ( !$ok ) {
            if ( $newFile ) {
                @unlink( $destination );
            }
            $this->errorMsg = 'Unable to import the complete file into AFS.';
            return false;
        }
        return $this->resolveExistingPath( $destination, 'file' ) !== false;
    }

    public function makeDirectory( $path, $recursive=true )
    {
        $path = $this->normalizeAbsolutePath( $path );
        if ( $path === false || !$this->pathWithinRoot( $path )) {
            $this->errorMsg = 'Directory target is outside the configured AFS root.';
            return false;
        }
        if ( $path === $this->dataRoot ) {
            return true;
        }

        $relative = substr( $path, strlen( $this->dataRoot ) + 1 );
        $segments = explode( '/', $relative );
        if ( !$recursive && count( $segments ) !== 1
          && !is_array( $this->pathLstat( dirname( $path )))) {
            $this->errorMsg = 'The parent AFS directory does not exist.';
            return false;
        }

        $current = $this->dataRoot;
        foreach ( $segments as $segment ) {
            if ( !$this->validLeafName( $segment )) {
                return false;
            }
            $current .= '/' . $segment;
            if ( is_array( $this->pathLstat( $current ))) {
                if ( $this->resolveExistingPath( $current, 'dir' ) === false ) {
                    return false;
                }
                continue;
            }
            if ( !@mkdir( $current, 0755, false )) {
                $this->errorMsg = 'Unable to create the AFS directory.';
                return false;
            }
            if ( $this->resolveExistingPath( $current, 'dir' ) === false ) {
                @rmdir( $current );
                return false;
            }
        }
        return true;
    }

    public function copyPath( $source, $destination, $update=true,
                              $force=true )
    {
        $source = $this->resolveExistingPath( $source );
        if ( $source === false || !$this->preflightRecursiveTree( $source )) {
            return false;
        }

        return $this->copyResolvedPath(
            $source, $destination, $update, $force );
    }

    public function renamePath( $source, $destination )
    {
        $source = $this->resolveObjectPath( $source );
        if ( $source === false || $source === $this->dataRoot ) {
            return false;
        }

        $sourceInfo = $this->inspectPath( $source, true );
        if ( $sourceInfo === false ) {
            return false;
        }
        if ( $sourceInfo['type'] === 'dir' ) {
            $mount = $this->probeAfsVolumeMountPoint( $source );
            if ( $mount === null || $mount !== false ) {
                $this->errorMsg = 'AFS volume mount objects cannot be renamed here.';
                return false;
            }
        }

        if ( is_array( $this->pathLstat( $destination ))) {
            $this->errorMsg = 'The destination already exists.';
            return null;
        }
        $destination = $this->resolveWritePath( $destination, false );
        if ( $destination === false ) {
            return false;
        }

        if ( !@rename( $source, $destination )) {
            $this->errorMsg = 'Unable to rename the AFS object.';
            return false;
        }

        $destinationInfo = $this->inspectPath( $destination, true );
        if ( $destinationInfo === false
          || $destinationInfo['type'] !== $sourceInfo['type'] ) {
            @rename( $destination, $source );
            $this->errorMsg = 'AFS rename post-validation failed.';
            return false;
        }
        return true;
    }

    public function removePath( $path )
    {
        $path = $this->resolveObjectPath( $path );
        $info = $path !== false ? $this->inspectPath( $path, true ) : false;
        if ( is_array( $info ) && $info['type'] === 'link' ) {
            return @unlink( $path );
        }
        if ( $path === false || $path === $this->dataRoot
          || !$this->preflightRecursiveTree( $path, true )) {
            return false;
        }
        return $this->removeResolvedPath( $path );
    }

    protected function resolveObjectPath( $path )
    {
        $path = $this->normalizeAbsolutePath( $path );
        if ( $path === false || !$this->pathWithinRoot( $path )) {
            $this->errorMsg = 'Object path is outside the configured AFS root.';
            return false;
        }
        if ( $path === $this->dataRoot ) {
            return $this->dataRoot;
        }
        $leaf = basename( $path );
        if ( !$this->validLeafName( $leaf )) {
            return false;
        }
        $parent = $this->resolveExistingPath( dirname( $path ), 'dir' );
        if ( $parent === false ) {
            return false;
        }
        $object = $parent . '/' . $leaf;
        $lstat = $this->pathLstat( $object );
        if ( !is_array( $lstat )) {
            return false;
        }
        if ( $this->statIsLink( $lstat )) {
            return $object;
        }
        return $this->resolveExistingPath( $object );
    }

    protected function resolveConfinedPath( $path, $type, $allowMissing )
    {
        if ( $this->dataRoot === '' ) {
            $this->errorMsg = 'AFS data-plane guard is not initialized.';
            return false;
        }

        $path = $this->normalizeAbsolutePath( $path );
        if ( $path === false || !$this->pathWithinRoot( $path )) {
            $this->errorMsg = 'Path is outside the configured AFS root.';
            return false;
        }

        if ( $path === $this->dataRoot ) {
            if ( $type === 'file' ) {
                return false;
            }
            return $this->dataRoot;
        }

        $relative = substr( $path, strlen( $this->dataRoot ) + 1 );
        $segments = explode( '/', $relative );
        $current = $this->dataRoot;
        $last = count( $segments ) - 1;

        foreach ( $segments as $index => $segment ) {
            if ( !$this->validLeafName( $segment )) {
                $this->errorMsg = 'Invalid AFS path component.';
                return false;
            }

            $current .= '/' . $segment;
            $lstat = $this->pathLstat( $current );
            if ( !is_array( $lstat )) {
                if ( $allowMissing && $index === $last ) {
                    return $current;
                }
                $this->errorMsg = 'AFS path does not exist.';
                return false;
            }
            if ( $this->statIsLink( $lstat )) {
                $this->errorMsg = 'POSIX symbolic links are not traversable in AFS mode.';
                return false;
            }

            $stat = $this->pathStat( $current );
            $real = $this->pathRealpath( $current );
            if ( !is_array( $stat ) || $real === false ) {
                $this->errorMsg = 'Unable to resolve the AFS path.';
                return false;
            }
            $real = $this->normalizeAbsolutePath( $real );
            if ( $real === false || !$this->pathWithinRoot( $real )) {
                $this->errorMsg = 'Resolved path escapes the configured AFS root.';
                return false;
            }
            if ( $real !== $this->dataRoot
              && $this->isKernelMountPoint( $real )) {
                $this->errorMsg = 'Kernel mount points are not traversable in AFS mode.';
                return false;
            }

            $identity = $this->probeAfsIdentity( $real, false );
            if ( !is_array( $identity )) {
                $this->errorMsg = 'Unable to verify AFS object identity.';
                return false;
            }

            $needsDirectory = $index < $last || $type === 'dir';
            if ( $needsDirectory && !$this->statIsDirectory( $stat )) {
                $this->errorMsg = 'AFS path component is not a directory.';
                return false;
            }
            if ( $this->statIsDirectory( $stat )) {
                $mount = $this->probeAfsVolumeMountPoint( $real );
                if ( $mount === null ) {
                    $this->errorMsg = 'Unable to classify an AFS volume mount point.';
                    return false;
                }
                if ( $mount !== false ) {
                    $this->crossedVolumeMounts[$real] = array(
                        'target' => $mount,
                        'identity' => $identity
                    );
                }
            }
            $current = $real;
        }

        $finalStat = $this->pathStat( $current );
        if ( $type === 'file' && !$this->statIsFile( $finalStat )) {
            $this->errorMsg = 'AFS object is not a regular file.';
            return false;
        }
        if ( $type === 'dir' && !$this->statIsDirectory( $finalStat )) {
            $this->errorMsg = 'AFS object is not a directory.';
            return false;
        }
        if ( $type === 'any' && !$this->statIsFile( $finalStat )
          && !$this->statIsDirectory( $finalStat )) {
            $this->errorMsg = 'Unsupported AFS object type.';
            return false;
        }

        return $current;
    }

    protected function validateOpenHandle( $handle, $path )
    {
        $handleStat = @fstat( $handle );
        $pathStat = $this->pathStat( $path );
        if ( !is_array( $handleStat ) || !is_array( $pathStat )
          || !$this->statIsFile( $handleStat )
          || $pathStat['dev'] != $handleStat['dev'] ) {
            return false;
        }

        if ( !empty( $handleStat['ino'] ) && !empty( $pathStat['ino'] )
          && $handleStat['ino'] != $pathStat['ino'] ) {
            return false;
        }

        unset( $this->identityCache['follow:' . $path] );
        unset( $this->identityCache['nofollow:' . $path] );
        return $this->resolveExistingPath( $path, 'file' ) === $path;
    }

    protected function writeAll( $handle, $contents )
    {
        $length = strlen( $contents );
        $written = 0;
        while ( $written < $length ) {
            $bytes = fwrite( $handle, substr( $contents, $written ));
            if ( $bytes === false || $bytes === 0 ) {
                return false;
            }
            $written += $bytes;
        }
        return true;
    }

    protected function searchDirectory( $base, $path, $filter, &$results )
    {
        $items = @scandir( $path );
        if ( !is_array( $items )) {
            return false;
        }
        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) {
                continue;
            }
            $child = $this->resolveExistingPath( $path . '/' . $item );
            if ( $child === false ) {
                // A symlink, kernel mount, or otherwise unresolvable entry is
                // not traversed and cannot leak search results.
                continue;
            }
            $stat = $this->pathStat( $child );
            if ( $this->statIsDirectory( $stat )) {
                $mount = $this->probeAfsVolumeMountPoint( $child );
                if ( $mount === null ) {
                    return false;
                }
                if ( $mount !== false ) {
                    // The caller can navigate into this child volume and start
                    // a new search there; a parent search never crosses it.
                    continue;
                }
                if ( !$this->searchDirectory( $base, $child, $filter, $results )) {
                    return false;
                }
            } elseif ( $this->statIsFile( $stat )
              && ( $filter === '' || stripos( $item, $filter ) !== false )) {
                $results[] = array(
                    'name' => $item,
                    'type' => 'file',
                    'path' => dirname( substr( $child, strlen( $base )))
                );
            }
        }
        return true;
    }

    protected function preflightRecursiveTree( $path, $allowLinks=false )
    {
        $info = $this->inspectPath( $path, $allowLinks );
        if ( $info === false ) {
            return false;
        }
        $path = $info['path'];
        if ( $info['type'] === 'link' ) {
            return $allowLinks;
        }
        if ( $info['type'] === 'file' ) {
            return true;
        }
        if ( $info['type'] !== 'dir' ) {
            return false;
        }

        $mount = $this->probeAfsVolumeMountPoint( $path );
        if ( $mount === null || $mount !== false ) {
            $this->errorMsg = 'Recursive mutation stops at an AFS volume mount point.';
            return false;
        }

        $items = @scandir( $path );
        if ( !is_array( $items )) {
            return false;
        }
        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) {
                continue;
            }
            $child = $path . '/' . $item;
            if ( !$this->preflightRecursiveTree( $child, $allowLinks )) {
                return false;
            }
        }
        return true;
    }

    protected function copyResolvedPath( $source, $destination, $update, $force )
    {
        $stat = $this->pathStat( $source );
        if ( $this->statIsFile( $stat )) {
            if ( is_array( $this->pathLstat( $destination )) && $update ) {
                $destinationSafe = $this->resolveExistingPath( $destination, 'file' );
                if ( $destinationSafe === false
                  || @filemtime( $destinationSafe ) >= @filemtime( $source )) {
                    return false;
                }
            }
            $sourceHandle = $this->openRead( $source );
            if ( $sourceHandle === false ) {
                return false;
            }
            $temporary = @tempnam( sys_get_temp_dir(), 'tinyfm-afs-copy-' );
            if ( $temporary === false ) {
                @fclose( $sourceHandle );
                return false;
            }
            $temporaryHandle = @fopen( $temporary, 'wb' );
            $ok = is_resource( $temporaryHandle );
            while ( $ok && !feof( $sourceHandle )) {
                $buffer = fread( $sourceHandle, 1024 * 1024 );
                if ( $buffer === false
                  || !$this->writeAll( $temporaryHandle, $buffer )) {
                    $ok = false;
                }
            }
            if ( $ok ) {
                $ok = @fflush( $temporaryHandle );
            }
            if ( is_resource( $temporaryHandle ) && !@fclose( $temporaryHandle )) {
                $ok = false;
            }
            if ( !@fclose( $sourceHandle )) {
                $ok = false;
            }
            if ( $ok ) {
                $ok = $this->importFile( $temporary, $destination, true, false );
            }
            if ( !@unlink( $temporary )) {
                $ok = false;
            }
            return $ok;
        }

        if ( !$this->statIsDirectory( $stat )) {
            return false;
        }

        $destinationNormalized = $this->normalizeAbsolutePath( $destination );
        if ( $destinationNormalized === false ) {
            return false;
        }
        $destinationParent = $this->resolveExistingPath(
            dirname( $destinationNormalized ), 'dir' );
        if ( $destinationParent === false
          || $destinationParent === $source
          || strpos( $destinationParent . '/', rtrim( $source, '/' ) . '/' ) === 0 ) {
            $this->errorMsg = 'Cannot copy a directory inside itself.';
            return false;
        }

        if ( is_array( $this->pathLstat( $destinationNormalized ))) {
            if ( $this->resolveExistingPath( $destinationNormalized, 'dir' ) === false ) {
                return false;
            }
        } elseif ( !$this->makeDirectory( $destinationNormalized, false )) {
            return false;
        }

        $items = @scandir( $source );
        if ( !is_array( $items )) {
            return false;
        }
        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) {
                continue;
            }
            if ( !$this->copyResolvedPath(
                    $source . '/' . $item,
                    $destinationNormalized . '/' . $item,
                    $update, $force )) {
                return false;
            }
        }
        return true;
    }

    protected function removeResolvedPath( $path )
    {
        $info = $this->inspectPath( $path, true );
        if ( $info === false ) {
            return false;
        }
        if ( $info['type'] === 'link' || $info['type'] === 'file' ) {
            return @unlink( $path );
        }
        if ( $info['type'] !== 'dir' ) {
            return false;
        }

        $items = @scandir( $path );
        if ( !is_array( $items )) {
            return false;
        }
        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) {
                continue;
            }
            if ( !$this->removeResolvedPath( $path . '/' . $item )) {
                return false;
            }
        }
        return @rmdir( $path );
    }

    protected function probeAfsIdentity( $path, $nofollow=false, $fresh=false )
    {
        $cacheKey = ( $nofollow ? 'nofollow:' : 'follow:' ) . $path;
        $arguments = array( 'getfid', '-path', $path );
        if ( $nofollow ) {
            $arguments[] = '-nofollow';
        }
        $output = $this->runFs( $arguments );
        if ( $output === false || $this->lastFsStatus !== 0
          || !preg_match( '/\(([0-9]+\.[0-9]+\.[0-9]+)\) contained in volume ([0-9]+)\s*$/',
                $output, $matches )) {
            return false;
        }

        $identity = array(
            'fid' => $matches[1],
            'volume' => $matches[2]
        );
        $this->identityCache[$cacheKey] = $identity;
        return $identity;
    }

    protected function probeAfsVolumeMountPoint( $path )
    {
        $output = $this->runFs( array( 'lsmount', '-dir', $path ));
        if ( $output !== false && $this->lastFsStatus === 0
          && preg_match( "/ is a mount point for volume '([^']+)'\\s*$/",
                $output, $matches )) {
            $this->volumeMountCache[$path] = $matches[1];
            return $matches[1];
        }
        if ( $output !== false && $this->lastFsStatus !== 0
          && preg_match( '/ is not a mount point\.\s*$/', $output )) {
            $this->volumeMountCache[$path] = false;
            return false;
        }

        $this->volumeMountCache[$path] = null;
        return null;
    }

    protected function loadKernelMountPoints()
    {
        $lines = @file( '/proc/self/mountinfo', FILE_IGNORE_NEW_LINES );
        if ( !is_array( $lines )) {
            return false;
        }

        $mounts = array();
        foreach ( $lines as $line ) {
            $fields = preg_split( '/\s+/', $line );
            if ( !isset( $fields[4] )) {
                return false;
            }
            $path = str_replace(
                array( '\\040', '\\011', '\\012', '\\134' ),
                array( ' ', "\t", "\n", '\\' ),
                $fields[4] );
            $path = $this->normalizeAbsolutePath( $path );
            if ( $path !== false ) {
                $mounts[] = $path;
            }
        }
        return array_values( array_unique( $mounts ));
    }

    protected function isKernelMountPoint( $path )
    {
        return is_array( $this->kernelMountPoints )
            && isset( $this->kernelMountPoints[$path] );
    }

    protected function normalizeAbsolutePath( $path )
    {
        if ( !is_string( $path ) || $path === ''
          || strpos( $path, "\0" ) !== false ) {
            return false;
        }
        $path = str_replace( '\\', '/', $path );
        if ( substr( $path, 0, 1 ) !== '/' ) {
            return false;
        }

        $clean = array();
        foreach ( explode( '/', $path ) as $segment ) {
            if ( $segment === '' ) {
                continue;
            }
            if ( $segment === '.' || $segment === '..' ) {
                return false;
            }
            $clean[] = $segment;
        }
        return '/' . implode( '/', $clean );
    }

    protected function validLeafName( $name )
    {
        return is_string( $name ) && $name !== '' && $name !== '.'
            && $name !== '..' && strpos( $name, '/' ) === false
            && strpos( $name, "\0" ) === false;
    }

    protected function pathWithinRoot( $path )
    {
        return $this->dataRoot !== ''
            && ( $path === $this->dataRoot
              || strpos( $path, $this->dataRoot . '/' ) === 0 );
    }

    protected function statIsLink( $stat )
    {
        return is_array( $stat ) && isset( $stat['mode'] )
            && ( $stat['mode'] & 0170000 ) === 0120000;
    }

    protected function statIsDirectory( $stat )
    {
        return is_array( $stat ) && isset( $stat['mode'] )
            && ( $stat['mode'] & 0170000 ) === 0040000;
    }

    protected function statIsFile( $stat )
    {
        return is_array( $stat ) && isset( $stat['mode'] )
            && ( $stat['mode'] & 0170000 ) === 0100000;
    }

    protected function pathLstat( $path )
    {
        clearstatcache( true, $path );
        return @lstat( $path );
    }

    protected function pathStat( $path )
    {
        clearstatcache( true, $path );
        return @stat( $path );
    }

    protected function pathRealpath( $path )
    {
        clearstatcache( true, $path );
        return @realpath( $path );
    }
}
