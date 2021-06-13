<?php  ## EV-soft - 2021-06-13
       ## to: Create / Update / Maintain list of translate strings by scanning the source-file(s)
       ## Place this file in the same folder as tinyfilemanager.php and read the file in your browser
    if (!isset($compareCode))
        $compareCode= 'ru'; ## Adjust this code to the default language you want to analyze (cant use 'en')
    $d = dir("./"); 
    $total= 0;    $buff= array();   $arrStrings= array(); $longest= 0;  $miss= 0;
    echo '<meta charset="utf-8">';
    echo "<br><big>".'Projektscann: '."</big><br>";
    echo "<br>".'Scanning for prefix: "lng(\'" '." in .php/.htm files in current folder,";
    echo "<br>and create a complete list of language texts that you can translate";
    echo '<p style="font-family:courier; font-size:18; ">'; 
    $arrTrans= [];  $arrCode= [];
    $content = file_get_contents('translation.json');
    if($content !== FALSE) {
        $lng = json_decode($content, TRUE);
        foreach ($lng["language"] as $key => $value) {
            $code = $value["code"];
            $lang_list[$code] = $value["name"];
            $arrTrans[$code] = $value["translation"];
            $arrCode[]= $code;
        }
    }
    echo '<form action="#" method="post">
          <label for="lngCode">Select a code:</label>
          <select id="lngCode" name="lngCode">';
    foreach ($arrCode as $code) echo '<option value="'.$code.'" '.($code==$compareCode ? 'selected ' : '').' >'.$code.'</option>';
    echo '</select>
        <input type="submit" name="submit" value="Analyze Selected" />
        </form>';
    if (isset($_POST['submit'])) $compareCode = $_POST['lngCode'];
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
                    if ($count>0) $buff[] = 'Total: '.$count.' found : "<font color=red>'.$search.'</font>" in file <i>'.$dir.'</i><b>'.$source.'</b><br>';
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
    echo '<br>Sorted list without duplicates for code: '.$compareCode;
    echo '<p style="font-family:courier; font-size:11; ">';
echo '<pre>
{
  "appName": "Tiny File Manager",
  "version": "2.4.6",
  "language": [
    {
      "name": "<font color=red>Fill: English name for the language</font>",
      "code": "<font color=red>Fill: language ISO code</font>",
      "translation": {';
        foreach ($arrStrings as $string) {
            if (strlen($string[0])>3) {
                echo '<br>'.str_repeat("&nbsp;",8).$string[0].':'.
                str_repeat("&nbsp;",$longest+3-strlen(utf8_decode(substr($string[0],0))));
            if (array_key_exists(trim($string[0],'"'),$arrTrans[$compareCode])) {
                echo '"'.$arrTrans[$compareCode][trim($string[0],'"')].'",'; 
                $miss++;
            }
            else echo '"<font color=red>Missing_native_translated_string</font>",';
            }};
echo ' <font color=red><- REMOVE THIS LAST COMMA !</font>
      }
    },
    {... Insert all other languages here ...}
  ]
}
</pre>';
  echo '</p>';
  echo '<br>Total: '.count($arrStrings).' strings i the sorted list. Longest string is on  '.$longest.' chars.';
  echo '<br>You can copy - paste this list to your editor';
  echo '<br><font color=red>Remember to escape the char: " </font>with a slash like this: \" if it occurs on translated text !';
  echo '<br>Status of the analyzed language is '.round($miss / count($arrStrings) * 100).' % translated.';
?>
