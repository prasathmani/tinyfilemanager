<?php
/*
 * Side-effect-free AFS production-provider contract.
 *
 * Tiny File Manager loads this before config.php so a deployment can load and
 * construct its reviewed factory without loading the legacy AFS helper (which
 * intentionally checks for POSIX/AFS runtime prerequisites at load time).
 */
interface AfsDataPlaneProviderFactory
{
    public function getFactoryIdentity();
    public function createProvider( $root, $requestIdentity );
}

interface AfsDataPlaneProvider
{
    const SECURITY_BOUNDARY_DESCRIPTOR_BENEATH_V1 =
        'descriptor-beneath-v1';

    public function initializeDataPlane( $root );
    public function isProductionReady();
    public function getReadinessFailure();
    public function getSecurityBoundary();
    public function getProviderIdentity();
    public function getCredentialIdentity();
    public function resolveExistingPath( $path, $type='any' );
    public function resolveWritePath( $path, $allowExisting=true );
    public function inspectPath( $path, $allowLinkObject=false );
    public function listDirectory( $path );
    public function searchFiles( $path, $filter='' );
    public function openRead( $path );
    public function readContents( $path );
    public function detectMimeType( $path );
    public function createFile( $path );
    public function writeFile( $path, $contents );
    public function importFile( $source, $destination, $overwrite=true,
                                $append=false );
    public function makeDirectory( $path, $recursive=true );
    public function copyPath( $source, $destination, $update=true,
                              $force=true );
    public function renamePath( $source, $destination );
    public function removePath( $path );
    public function archivesSupported();
    public function readAcl( $path='' );
    public function changeAclEntries( $entries, $path='', $negative=false );
    public function getACLAccess( $path );
}
