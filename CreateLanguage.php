<?php  ## EV-soft - 2021-06-13
       ## to: Create / Update / Maintain list of translate strings by scanning the source-file(s)
       ## Place this file in the same folder as tinyfilemanager.php and read the file in your browser
    $d = dir("./"); 
    $total= 0;    $buff= array();   $arrStrings= array(); $longest= 0;
    echo "<br><big>".'Projektscann: '."</big><br>";
    echo "<br>".'Scanning for prefix: "lng(\'" '." in .php/.htm files in current folder,";
    echo "<br>and create a complete list of language texts that you can translate";
    echo '<p style="font-family:courier; font-size:18; ">'; 

    while (false !== ($entry = $d->read())) {
    $dir= $entry.'/';
    if (is_dir($entry) ) {
        $files = scandir($dir);
        if ($files)
        foreach ($files as $source) { $count= 0;  $search= "lng('";
            if (($source!=='.') and ($source!=='..') 
                and (!strpos($source,'.bak')) and (!strpos($source,'lngScann.php')) and (!strpos($source,'.csv')) 
                and ((strpos($source,'.php')) or (strpos($source,'.htm'))) ) 
                {   $lines = file($dir.$source); 
                    foreach ($lines as $line_num => $line) {
                    $line= ' '.$line;
                    if ($a=strpos($line,$search)) {
                            if ((strpos($source,'.php')) or (strpos($source,'.htm'))) {
                            $str= $line;
                            while (strpos($str,$search)) {
                                    $a= strpos($str,$search);  $str= substr($str,$a+5);  $b= strpos($str,"')");
                                    $str= html_entity_decode($str);
                                    $str= strip_tags($str);
                                    $longest= max($longest,strlen(utf8_decode(substr($str,0,$b))));
                                    $f= substr($str,0,$b);
                                    $arrStrings[] = ['"'.$f.'"'];
                                } 
                            } $count++; $total++;
                        }
                    }
                    $count= substr('000'.$count,-4);
                    if ($count>0) $buff[] = 'Total: '.$count.' found : "<font color=red>'.$search.'</font>" i <i>'.$dir.'</i><b>'.$source.'</b><br>';
                } 
            }
        }
    }
    echo '</p>';
    $d->close();
    foreach ($buff as $buf) {echo $buf;};
    echo '<br>Total: '.$total. ' found: <i>'.$search.'</i> in the scanned files<br>';
    $arrStrings= array_unique($arrStrings, SORT_REGULAR);
    // sort($arrStrings, SORT_NATURAL | SORT_FLAG_CASE);
    sort($arrStrings);
    echo '<br>Sorted list without duplicates:';
    echo '<p style="font-family:courier; font-size:11; ">';
echo '<pre>
{
  "appName": "Tiny File Manager",
  "version": "2.4.6",
  "language": [
    {
      "name": "Fill: English name for the language",
      "code": "Fill: language ISO code",
      "translation": {';
        foreach ($arrStrings as $string) 
        {if (strlen($string[0])>3) 
            echo '<br>'.str_repeat("&nbsp;",8).$string[0].':'.
            str_repeat("&nbsp;",$longest+3-strlen(utf8_decode(substr($string[0],0)))).
            '"Missing_native_translated_string",';
        };
echo ' <- REMOVE THIS LAST COMMA !
      }
    },
    {... Insert all other languages here ...}
  ]
}
</pre>';
  echo '</p>';
  echo '<br>Total: '.count($arrStrings).' strings i the sorted list. Longest string is on  '.$longest.' chars.';
  echo '<br>You can copy - paste this list to your editor';
  echo '<br>Remember to escape the char: " with a slash like this: \" if it occurs on translated text !';
?>
