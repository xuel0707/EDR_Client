#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdio.h>
#include <stdlib.h>
#include <pcre.h>

#include "../cJSON.h"
#include "sys_info.h"

extern int is_dir(const char *file);
extern void delete_tailspace(char *str);

////////////////////////////////////////////////////////////////
///////////          web  framework                  ///////////
////////////////////////////////////////////////////////////////
#define WEBFRAME_Drupal         0
#define WEBFRAME_Phalcon        1
#define WEBFRAME_Webasyst       2
#define WEBFRAME_Flask          3
#define WEBFRAME_Tornado        4
#define WEBFRAME_ThinkCMF       5
#define WEBFRAME_Laravel        6
#define WEBFRAME_Webpy          7
#define WEBFRAME_Web2py         8
#define WEBFRAME_Kyphp          9
#define WEBFRAME_CI             10
#define WEBFRAME_YII            11
#define WEBFRAME_CAKEPHP        12
#define WEBFRAME_INITPHP        13
#define WEBFRAME_SPEEDPHP       14
#define WEBFRAME_THINKPHP       15
#define WEBFRAME_COTONTI        16
#define WEBFRAME_MODX           17
#define WEBFRAME_TYPO3          18
#define WEBFRAME_CANPHP         19
#define WEBFRAME_ONETHINK       20
#define WEBFRAME_AGILETOOLKIT   21
#define WEBFRAME_BEDITA         22
#define WEBFRAME_CORETHINK      23
#define WEBFRAME_CDVPHP         24
#define WEBFRAME_FLIGHT         25
#define WEBFRAME_PHPIXIE        26


#define WEBFRAME_STRUTS         27
#define WEBFRAME_STRUTS2        28
#define WEBFRAME_SPRING         29
#define WEBFRAME_SPRINGMVC      30
#define WEBFRAME_DJANGO         31
static char web_framework[64] = {0};

typedef struct _webframe_info {
    char cheak_file[PATH_MAX];
    char regex[128];
    char name[64];
    char language[64];
    int type;
    int flag;
} web_frame_t;

/* 注释的部分，是框架检测存在冲突的文件
 * 以下全部是PHP类的框架正则
 */
static web_frame_t web_frame_info[] = {
    // Drupal
    {"/cron.php", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/includes/utility.inc", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/misc/ajax.js", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/modules/node/node.js", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/includes/database/sqlite/schema.inc", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/core/core.api.php", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/core/authorize.php", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    // {"/composer.json", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/vendor/composer/autoload_static.php", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    // {"/index.php", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/vendor/autoload.php", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/update.php", "\0", "Drupal", "PHP", WEBFRAME_Drupal, 1},
    {"/CHANGELOG.txt", "(?<=Drupal\\s)((\\d)+(\\.(\\d)+)+)", "Drupal", "PHP", WEBFRAME_Drupal, 0},
    {"/core/lib/Drupal.php", "(?<=VERSION\\s\\=\\s\\')((\\d)+(\\.(\\d)+)+)", "Drupal", "PHP", WEBFRAME_Drupal, 0},
    // Phalcon
    {"/appveyor.yml", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/BACKERS.md", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/build/gen-build.php", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/build/install", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/build/php5/32bits/config.m4", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/build/php5/32bits/phalcon.zep.c", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/ext/config.m4", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/ext/kernel/array.c", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/ext/phalcon/crypt.zep.c", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/ext/phalcon/crypt.zep.h", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phalcon/acl.zep", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phalcon/validationinterface.zep", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phalcon/version.zep", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/bootstrap/autoload.php", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phalcon-completion.bash", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phalcon.php", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phalcon.sh", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phpcs.xml.dist", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/phpstan.neon", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    // {"/README.md", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    // {"/composer.json", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/config.py", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/devtools/ide/gen-stubs.php", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/devtools/ide/phpstorm/phalcon.sh", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/devtools/phalcon.php", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/devtools/README.md", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/ext/config.c", "\0", "Phalcon", "PHP", WEBFRAME_Phalcon, 1},
    {"/config.json", "(?<=version\\\"\\:\\s\\\")((\\d)+(\\.(\\d)+)+)", "Phalcon", "PHP", WEBFRAME_Phalcon, 0},
    {"/appveyor.yml", "(?<=version\\:\\s)((\\d)+(\\.(\\d)+)+)", "Phalcon", "PHP", WEBFRAME_Phalcon, 0},
    {"/ext/php_phalcon.h", "(?<=PHP\\_PHALCON\\_VERSION\\s\\\")(Phalcon\\d.*\\-(\\d)+(\\.(\\d)+)+)", "Phalcon", "PHP", WEBFRAME_Phalcon, 0},
    {"/.travis.yml", "(?<=PHALCON\\_VERSION\\=\\\"v)((\\d)+(\\.(\\d)+)+)", "Phalcon", "PHP", WEBFRAME_Phalcon, 0},
    // PHPixie
    // {"/composer.json", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    // {"/README.md", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    {"/src/Project/Framework/Bundles.php", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    {"/src/Project/Framework/Builder.php", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    {"/src/Project/Framework/Extensions.php", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    {"/src/Project/Framework.php", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    // {"/composer.json", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    // {"/README.md", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 1},
    {"/composer.lock", "\0", "PHPixie", "PHP", WEBFRAME_PHPIXIE, WEBFRAME_PHPIXIE},
    {"/bundles/app/assets/templates/layout.php", "(?<=PHPixie\\s)((\\d)+(\\.(\\d)+)+)", "PHPixie", "PHP", WEBFRAME_PHPIXIE, 0},
    // webasyst
    {"/wa-system/request/waRequestFile.class.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa-system/controller/waForgotPasswordAction.class.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa-system/datetime/waDateTime.class.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa-system/contact/waContactField.class.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa-installer/install.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa-installer/lib/config/sources.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa-installer/lib/init.php", "\0", "Webasyst", "PHP", WEBFRAME_Webasyst, 1},
    {"/wa-system/webasyst/lib/config/app.php", "(?<=version'\\s=>\\s')((\\d)+(\\.(\\d)+)+)", "Webasyst", "PHP", WEBFRAME_Webasyst, 0},
    // Flight
    // {"/composer.json", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/flight/autoload.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/flight/core/Loader.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/flight/Engine.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/flight/Flight.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/flight/net/Request.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/flight/template/View.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/flight/util/Collection.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    // {"/index.php", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    // {"/README.md", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/tests/README.md", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, 1},
    {"/vendor/mikecao/flight/VERSION", "\0", "Flight", "PHP", WEBFRAME_FLIGHT, WEBFRAME_FLIGHT},
    {"/VERSION", "((\\d)+(\\.(\\d)+)+)", "Flight", "PHP", WEBFRAME_FLIGHT, 0},
    // CdvPHP
    {"/Application/Controller/Index.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/BasePdo/BasePdo.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/Loader/Autoloader.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/Mvc/Application.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/Session/Session.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/Sign/Sign.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/Superglobal/Superglobal.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/Timer/Timer.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/CdvPHP/View/View.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/Project/autoload_builder.sh", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/Public/index.php", "\0", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 1},
    {"/Application/Controller/Index.php", "(?<=CdvPHP\\s)((\\d)+(\\.(\\d)+)+)", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 0},
    {"/Application/View/Templates/header.html", "(?<=CdvPHP\\s)((\\d)+(\\.(\\d)+)+)", "CdvPHP", "PHP", WEBFRAME_CDVPHP, 0},
    // thinkCMF
    {"/plugins/Demo/config.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/plugins/Demo/View/widget.html", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/data/runtime/Data/site_options.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/data/runtime/Data/site_nav_main.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/app/admin/annotation/AdminMenuAnnotation.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/app/admin/api/NavApi.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/app/admin/hooks.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/app/command.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/app/config.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/app/release.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/app/route.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    // {"/composer.json", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/public/index.php", "\0", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 1},
    {"/index.php", "(?<=SIMPLEWIND_CMF_VERSION.,\\s')((\\d)+(\\.(\\d)+)+)", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 0},
    {"/public/index.php", "(?<=THINKCMF\\_VERSION\\\'\\,\\s\\\')((\\d)+(\\.(\\d)+)+)", "THinkCMF", "PHP", WEBFRAME_ThinkCMF, 0},
    // Laravel
    {"/server.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/public/index.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/config/view.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/config/session.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/config/queue.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/config/mail.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/config/logging.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/config/database.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/config/app.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    // {"/composer.json", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/bootstrap/app.php", "\0", "Laravel", "PHP", WEBFRAME_Laravel, 1},
    {"/composer.json", "(?<=laravel\\/framework\\\"\\:\\s\\\")((\\d)+((\\.)(\\d)+)+)", "Laravel", "PHP", WEBFRAME_Laravel, 0},
    // CoreThink
    // {"/index.php", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Addons/RocketToTop/RocketToTopAddon.class.php", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/admin.php", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Data/dev.php", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Application/Common/Util/Sql.class.php", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Application/Common/Builder/ListBuilder.class.php", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Application/Home/View/Public/think/exception.html", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Application/Admin/View/Index/index.html", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Application/Common/Conf/config.php", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/LICENSE.txt", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    // {"/README.md", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, 1},
    {"/Application/Admin/opencmf.php", "(?<='version'\\s{5}=>\\s')((\\d)+(\\.(\\d)+)+)", "CoreThink", "PHP", WEBFRAME_CORETHINK, 0},
    {"/Application/Install/Data/install.sql", "\0", "CoreThink", "PHP", WEBFRAME_CORETHINK, WEBFRAME_CORETHINK},
    // Kyphp
    {"/blog/inc/config.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/blog/index.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/blog/log/error.txt", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/example_gbk/exam_cache/index.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/example_gbk/hello/index.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/example_utf8/manage/index.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/example_utf8/test/index.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/kyphp/kyclass/kyphp_base/Action.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/kyphp/kyclass/kyphp_base/Cache.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/kyphp/kycmd/message.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/kyphp/kyphp.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/kyphp/kycmd/cmd.php", "\0", "KYPHP", "PHP", WEBFRAME_Kyphp, 1},
    {"/kyphp/kyphp.php", "(?<=version\\s\\s)((\\d)+(\\.(\\d)+)+)", "KYPHP", "PHP", WEBFRAME_Kyphp, 0},
    // CodeIgniter
    {"/application/config/config.php", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    // {"/composer.json", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    // {"/index.php", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/user_guide/tutorial/create_news_items.html", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/user_guide/searchindex.js", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/system/database/DB.php", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/contributing.md", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/application/config/constants.php", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/user_guide/index.html", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/system/libraries/Parser.php", "\0", "CodeIgniter", "PHP", WEBFRAME_CI, 1},
    {"/system/core/CodeIgniter.php", "(?<=const\\sCI\\_VERSION\\s=\\s.)((\\d)+((\\.)(\\d)+)+)", "CodeIgniter", "PHP", WEBFRAME_CI, 0},
    // AgileToolkit
    {"/agiletoolkit-sandbox.phar", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/admin/public/index.php", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/admin/page/index.php", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/vendor/atk4/atk4/tools/project-update.sh", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    // {"/vendor/composer/installed.json", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    // {"/.gitignore", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    // {"/composer.lock", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    // {"/index.php", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/frontend/public/atk4/css/theme.css", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/frontend/page/index.php", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/run.sh", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/vendor/atk4/core/.travis.yml", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/vendor/atk4/core/composer.json", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/vendor/atk4/core/README.md", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/vendor/atk4/ui/CHANGELOG.md", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/vendor/atk4/ui/composer.json", "\0", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 1},
    {"/composer.lock", "(?<=version\\\"\\:\\s\\\")((\\d)+(\\.(\\d)+)+)", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 0},
    {"/vendor/atk4/ui/src/App.php", "(?<=version\\s\\=\\s\\')((\\d)+(\\.(\\d)+)+)", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 0},
    {"/vendor/atk4/atk4/composer.json", "(?<=.version.:\\s.)((\\d)+(\\.(\\d)+)+)", "AgileToolkit", "PHP", WEBFRAME_AGILETOOLKIT, 0},
    // OneThink
    {"/Application/Common/Common/function.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/Addons/DevTeam/config.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/Addons/SiteStat/config.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    // {"/index.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/readme.html", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/Application/Home/Logic/ArticleLogic.class.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/Application/Admin/Conf/config.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/Application/Admin/View/Addons/index.html", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/Application/User/Service/Service.class.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/Application/User/Common/common.php", "\0", "OneThink", "PHP", WEBFRAME_ONETHINK, 1},
    {"/readme.html", "(?<=Version\\s)((\\d)+(\\.(\\d)+)+)", "OneThink", "PHP", WEBFRAME_ONETHINK, 0},
    {"/Application/Common/Common/function.php", "(?<=ONETHINK_VERSION\\s\\s\\s\\s=\\s')((\\d)+(\\.(\\d)+)+)", "OneThink", "PHP", WEBFRAME_ONETHINK, 0},
    // // Bedita
    {"/bedita-app/libs/xml_json_converter.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/libs/be_callback_manager.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/config/bedita.ini.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/bedita_exception.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/views/users/inc/form_user.tpl", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/frontends/responsive/config/frontend.ini.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/vendors/rcs.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/vendors/hyphenator/Hyphenator.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/controllers/login/authentications_controller.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/models/business/data_transfer.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/app_controller.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/app_error.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/app_model.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/CHANGES.md", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/setup/setup.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/models/utility.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/config/sql/schema.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/bedita_exception.php", "\0", "Bedita", "PHP", WEBFRAME_BEDITA, 1},
    {"/bedita-app/config/bedita.ini.php", "(?<=version\\'\\]\\s\\=\\s\\\')((\\d)+(\\.(\\d)+)+)", "Bedita", "PHP", WEBFRAME_BEDITA, 0},
    {"/bedita-app/config/bedita.ini.php", "(?<=BEdita\\s)((\\d)+(\\.(\\d)+)+)", "Bedita", "PHP", WEBFRAME_BEDITA, 0},
    // CanPHP
    {"/CanPHP/ext/extend.php", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/CanPHP/ext/IpArea.class.php", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/template/index_index.html", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/CanPHP/LICENSE.txt", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/template/index_show.html", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    // {"/composer.json", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/framework/ext/Email.php", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/framework/ext/send/EmailDriver.php", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    // {"/README.md", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/config.php", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/app/main/view/default_index.html", "\0", "CanPHP", "PHP", WEBFRAME_CANPHP, 1},
    {"/config.php", "(?<=ver']=)((\\d)(\\.\\d+)+)", "CanPHP", "PHP", WEBFRAME_CANPHP, 0},
    {"/app/main/view/default_index.html", "(?<=Canphp)((\\d)(\\.\\d+)+)", "CanPHP", "PHP", WEBFRAME_CANPHP, 0},
    // Yii
    {"/framework/yii", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/framework/base/Application.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/framework/console/controllers/MessageController.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/framework/web/Session.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/tests/TestCase.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/composer.lock", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/build/controllers/ReleaseController.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/phpunit.xml.dist", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    // {"/composer.json", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/cs/src/YiiConfig.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/yii.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/yiilite.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/yiit.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/web/actions/CAction.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/web/actions/CViewAction.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/web/actions/CInlineAction.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/web/auth/CAccessControlFilter.php", "\0", "Yii", "PHP", WEBFRAME_YII, 1},
    {"/BaseYii.php", "(?<=return\\s.)((\\d)+(\\.(\\d)+)+)", "Yii", "PHP", WEBFRAME_YII, 0},
    {"/YiiBase.php", "(?<=return\\s.)((\\d)+(\\.(\\d)+)+)", "Yii", "PHP", WEBFRAME_YII, 0},
    {"/yiilite.php", "(?<=return\\s.)((\\d)+(\\.(\\d)+)+)", "Yii", "PHP", WEBFRAME_YII, 0},
    {"/vendor/yiisoft/yii2/BaseYii.php", "(?<=return\\s.)((\\d)+(\\.(\\d)+)+)", "Yii", "PHP", WEBFRAME_YII, 0},
    {"/basic/vendor/yiisoft/yii2/BaseYii.php", "(?<=return\\s.)((\\d)+(\\.(\\d)+)+)", "Yii", "PHP", WEBFRAME_YII, 0},
    // TYPO3
    {"/typo3/sysext/rtehtmlarea/Resources/Public/JavaScript/HTMLArea/Editor/Framework.js", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"/CONTRIBUTING.md", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"/vendor/composer/autoload_alias_loader_real.php", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"/vendor/typo3fluid/fluid/src/Core/Parser/Configuration.php", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    // {"/index.php", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    // {"/composer.json", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"/.gitreview", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"/typo3/sysext/info/composer.json", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"/dynamicReturnTypeMeta.json", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"typo3/sysext/dbal/Documentation/Extensions/SqlStandard/Index.rst", "\0", "Typo3", "PHP", WEBFRAME_TYPO3, 1},
    {"/typo3/sysext/core/Classes/Core/SystemEnvironmentBuilder.php", "(?<=TYPO3_version',\\s')((\\d)(\\.\\d+)+)", "Typo3", "PHP", WEBFRAME_TYPO3, 0},
    // CakePHP
    {"/tests/Fixture/TagsTranslationsFixture.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/tests/Fixture/MenuLinkTreesFixture.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/phpcs.xml.dist", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    // {"/composer.json", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/config/bootstrap.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/src/Event/EventManager.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/src/View/View.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/src/Database/TypeMapTrait.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/config/config.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/src/Core/App.php", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 1},
    {"/VERSION.txt", "((\\d)+(\\.(\\d)+)+)$", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 0},
    {"/vendor/composer/installed.json", "\0", "CakePHP", "PHP", WEBFRAME_CAKEPHP, WEBFRAME_CAKEPHP},
    {"/src/Filesystem/Folder.php", "(?<=@since\\s+)((\\d)+((\\.)(\\d)+)+)", "CakePHP", "PHP", WEBFRAME_CAKEPHP, 0},
    // MODx
    {"/manager/assets/modext/core/modx.js", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/core/packages/core/modMenu/ac628df1a0286389772348f66a0d5aaf.vehicle", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/manager/assets/modext/core/modx.localization.js", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/core/model/modx/modmanagercontroller.class.php", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/core/model/modx/modmanagercontroller.class.php", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/core/lexicon/ru/source.inc.php", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/manager/templates/default/browser/index.tpl", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/connectors/lang.js.php", "\0", "MODx", "PHP", WEBFRAME_MODX, 1},
    {"/core/docs/changelog.txt", "(?<=MODX\\sRevolution\\s)((\\d)+(\\.(\\d)+)+)", "MODx", "PHP", WEBFRAME_MODX, 0},
    // InitPHP
    {"/demo/app/conf/comm.conf.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/demo/www/index.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/core/controller/controller.init.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/core/controller/filter.init.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/core/controller/request.init.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/core/service/service.init.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/core/util/cookie.init.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/initphp.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/init/run.init.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/initphp/init/core.init.php", "\0", "InitPHP", "PHP", WEBFRAME_INITPHP, 1},
    {"/README", "(?<=InitPHP\\sV)((\\d)+(\\.(\\d)+)+)", "InitPHP", "PHP", WEBFRAME_INITPHP, 0},
    // Cotonti
    {"/themes/symisun-03/header.tpl", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/system/admin/admin.home.php", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/modules/install/tpl/install.update.tpl", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/system/admin/tpl/header.tpl", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/system/admin/admin.home.php", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/themes/nemesis/css/extras.css", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/login.php", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/admin.php", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    // {"/index.php", "\0", "Cotonti", "PHP", WEBFRAME_COTONTI, 1},
    {"/system/functions.php", "(?<=version\\'\\]\\s=\\s')((\\d)+(\\.(\\d)+)+)", "Cotonti", "PHP", WEBFRAME_COTONTI, 0},
    // SpeedPHP
    {"/Core/spController.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Core/spModel.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Drivers/mssql.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Drivers/oracle.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Drivers/pdo.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Drivers/sae.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Drivers/speedy.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Drivers/sqlite.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Extensions/spAccessCache.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/spConfig.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/SpeedPHP.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/spFunctions.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Core/Db/mysql.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Core/spView.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Core/mysql.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/LICENSE.txt", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Extensions/spAcl.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Extensions/spDB.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/Extensions/spUrlRewrite.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/LICENSE", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/protected/view/layout.html", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/protected/view/main_index.html", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/LICENSE", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/protected/config.php", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    // {"/README.md", "\0", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 1},
    {"/SpeedPHP.php", "(?<=SP\\_VERSION'\\,\\s\\\')((\\d)+(\\.(\\d)+)+)", "SpeedPHP", "PHP", WEBFRAME_SPEEDPHP, 0},
    // ThinkPHP
    {"/application/common.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/build.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/config/app.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/config/cache.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/LICENSE.txt", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/public/index.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/route/route.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/thinkphp/start.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/thinkphp/console.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/thinkphp/base.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    // {"/composer.json", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/Application/Home/Controller/IndexController.class.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/ThinkPHP/Mode/Sae/convention.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/ThinkPHP/Conf/convention.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    // {"/ThinkPHP/ThinkPHP.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/ThinkPHP/Library/Think/Controller/RestController.class.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/config/app.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/build.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/public/index.php", "\0", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 1},
    {"/thinkphp/base.php", "(?<='THINK_VERSION',\\s')((\\d)+(\\.(\\d)+)+)", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 0},
    {"/ThinkPHP.php", "(?<=THINK_VERSION\\s\\s\\s\\s\\s=\\s\\s\\s')((\\d)+(\\.(\\d)+)+)", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 0},
    {"/ThinkPHP.php", "(?<=THINK_VERSION\\s=\\s')((\\d)+(\\.(\\d)+)+)", "", "PHP", WEBFRAME_THINKPHP, 0},
    {"/ThinkPHP/Common/runtime.php", "(?<='THINK_VERSION',\\s')((\\d)+(\\.(\\d)+)+)", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 0},
    // {"/ThinkPHP/ThinkPHP.php", "(?<=THINK_VERSION\\s\\s\\s\\s\\s=\\s\\s\\s')((\\d)+(\\.(\\d)+)+)", "", "PHP", WEBFRAME_THINKPHP, 0},
    {"/CHANGELOG.md", "(?<=V)((\\d)+((\\.)(\\d)+)+)", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 0},
    {"/library/think/App.php", "(?<=VERSION\\s\\=\\s\\')((\\d)+((\\.)(\\d)+)+)", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 0},
    {"/ThinkPHP/ThinkPHP.php", "(?<=THINK\\_VERSION\\s\\=\\s\\')((\\d)+((\\.)(\\d)+)+)", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 0},
    {"/Common/runtime.php", "(?<='THINK_VERSION',\\s')((\\d)+(\\.(\\d)+)+)", "ThinkPHP", "PHP", WEBFRAME_THINKPHP, 0},
    {'\0', '\0', -1, -1}
    };

////////////////////////////////////////////////////////////////
///////////          web  site                       ///////////
////////////////////////////////////////////////////////////////
#define SITE_WORDPRESS          0
#define SITE_THINKPHP           1
#define SITE_JENKINS            2
#define SITE_MAX                3

typedef struct _site_info {
    char home_dir[PATH_MAX];
    char home_dir_user[PATH_MAX];
    char domain[NAME_MAX];
    char port[NAME_MAX];
    char pid[64];
    char run_user[32];
    char protocol[32];
    char service_type[16];
    int is_found;
    char port_status[1];
} web_site_t;

static web_site_t site_info[SITE_MAX];

static int is_filename_in_dir(const char *path, const char *filename, char *result, const int result_len);
static int find_key_from_file(const char *file_path, const char *key, char *buf, const unsigned buf_len, const int flag);

static int supplement_apache_info(web_site_t *web_info)
{
    char line[PATH_MAX];
    char ports[PATH_MAX];
    struct stat buf;
    FILE *fp = NULL;
    char *tmp = NULL;
    char *iterm_port = NULL;
    int offset = 0;
    int len = 0;
    int ret = 0;

    if (web_info == NULL) return -1;

    /* home_dir_user */
    memset(&buf, 0x00, sizeof(buf));
    if (stat(web_info->home_dir, &buf) == 0) {
        uidtoname(buf.st_uid, web_info->home_dir_user, sizeof(web_info->home_dir_user));
    }
    else {
        snprintf(web_info->home_dir_user, sizeof(web_info->home_dir_user), "%s", "None");
    }

    /* protocol http or https */
#ifdef SNIPER_FOR_DEBIAN
    fp = fopen("/etc/apache2/apache2.conf", "r");
#else
    fp = fopen("/etc/httpd/conf/httpd.conf", "r");
#endif
    if (fp == NULL) { /* default */
        snprintf(web_info->protocol, sizeof(web_info->protocol), "%s", "None");
        snprintf(web_info->port, sizeof(web_info->port), "%s", "None");
    }
    else {
        memset(line, 0x00, sizeof(line));
        memset(ports, 0x00, sizeof(ports));
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (line[0] == '#' || line[0] == '<' || line[0] == '\n') continue;
            
            if (strstr(line, "LoadModule")) { /* https */
                tmp = strstr(line, "mod_ssl.so");
                if (tmp) {
                    snprintf(web_info->protocol, sizeof(web_info->protocol), "%s", "https");
                }
                continue;
            }

            if (strncmp(line, "Listen", 6) == 0) { /* get port */
                iterm_port = line;
                iterm_port += 7;
                if (*iterm_port == ' ') {
                    snprintf(web_info->port_status, sizeof(web_info->port_status), "%s", "1");
                } else {
                    snprintf(web_info->port_status, sizeof(web_info->port_status), "%s", "0");
                }
                iterm_port = strchr(line, ' ');
                ++ iterm_port;
                len = strlen(iterm_port);
                if (iterm_port[len-1] == '\n') iterm_port[len-1] = '\0';
                if (!offset) {
                    snprintf(ports+offset, sizeof(ports)-offset, "%s", iterm_port);
                }
                else {
                    snprintf(ports+offset, sizeof(ports)-offset, ",%s", iterm_port);
                }
                offset = strlen(iterm_port);
                continue;
            }
            /* domain */
            tmp = NULL;
            tmp = strstr(line, "ServerName");
            if (tmp) {
                tmp += 10;
                snprintf(web_info->domain, sizeof(web_info->domain), "%s", trim_space(tmp));
                continue;
            }
        }
        fclose(fp);
    }
    if (!web_info->protocol[0]) {
        snprintf(web_info->protocol, sizeof(web_info->protocol), "%s", "http");
    }
#ifdef SNIPER_FOR_DEBIAN
    /* get apache2 ports */
    fp = fopen("/etc/apache2/ports.conf", "r");
    if (fp) {
        memset(line, 0x00, sizeof(line));
        memset(ports, 0x00, sizeof(ports));
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (line[0] == '#' || line[0] == '<' || line[0] == '\n') continue;
            if (strncmp(line, "Listen", 6) == 0) { /* get port */
                tmp = line + 7;
                if (strncmp(tmp, "0.0.0.0", 7) == 0) {
                    snprintf(web_info->port_status, sizeof(web_info->port_status), "%s", "1");
                } else if (strncmp(tmp, "127.0.0.1", 9) == 0) {
                    snprintf(web_info->port_status, sizeof(web_info->port_status), "%s", "2");
                } else {
                    snprintf(web_info->port_status, sizeof(web_info->port_status), "%s", "0");
                }
                iterm_port = strchr(line, ':');
                 if (iterm_port) {
                    ++ iterm_port;
                    snprintf(ports, sizeof(ports), "%s", iterm_port);
                    offset = strlen(iterm_port);
                } else {
                    tmp = line + 7;
                    while(*tmp == ' ' || *tmp == '\t') {
                        tmp ++;
                    }
                    offset = strlen(tmp);
                    snprintf(ports, sizeof(ports), "%s", tmp);
                    ports[offset-1] = '\0';
                }
            }
        }
        fclose(fp);
    }
    len = strlen(ports);
    if (ports[len] == '\n') {
        ports[len] = '\0';
    }
#endif
    if (offset) {
        snprintf(web_info->port, sizeof(web_info->port), "%s", ports);
    }
    else {
        snprintf(web_info->port, sizeof(web_info->port), "%s", "None");
    }
    
    if (!web_info->domain[0]) {
        snprintf(web_info->domain, sizeof(web_info->domain), "%s", "None");
    }

    return ret;
}

/* JSON web_site 
 * 域名在检测apache/nginx中间件的时候一起检测了
 */
void *sys_web_site_info(sys_info_t *data)
{
    int i = 0;

    if (data->object == NULL) return NULL;

    for (i = 0; i <= SITE_MAX; i++) {
        if (site_info[i].is_found) {
            /* 如果没找到域名不上报 */
            if (!site_info[i].domain[0] || strcmp(site_info[i].domain, "None") == 0) {
                continue;
            }
            cJSON *object = cJSON_CreateObject();
            cJSON_AddItemToArray(data->object, object);
            cJSON_AddStringToObject(object, "domain", site_info[i].domain);
            cJSON_AddStringToObject(object, "home_dir", site_info[i].home_dir);
            cJSON_AddStringToObject(object, "home_dir_user", site_info[i].home_dir_user);
            cJSON_AddStringToObject(object, "run_user", site_info[i].run_user);
            struct stat buf;
            char user_perm[64] = {0};
            if (stat(site_info[i].home_dir, &buf) == 0) {
                user_perm[0] = (buf.st_mode & S_IRUSR) ? 'r' : '-';
                user_perm[1] = (buf.st_mode & S_IWUSR) ? 'w' : '-';
                user_perm[2] = (buf.st_mode & S_IXUSR) ? 'x' : '-';
                /* group */
                user_perm[3] = (buf.st_mode & S_IRGRP) ? 'r' : '-';
                user_perm[4] = (buf.st_mode & S_IWGRP) ? 'w' : '-';
                user_perm[5] = (buf.st_mode & S_IXGRP) ? 'x' : '-';
                /* others */
                user_perm[6] = (buf.st_mode & S_IROTH) ? 'r' : '-';
                user_perm[7] = (buf.st_mode & S_IWOTH) ? 'w' : '-';
                user_perm[8] = (buf.st_mode & S_IXOTH) ? 'x' : '-';
            } else {
                snprintf(user_perm, sizeof(user_perm), "%s", "---------");
            }
            cJSON_AddStringToObject(object, "user_perm", user_perm);
            cJSON_AddStringToObject(object, "protocol", site_info[i].protocol);
            cJSON_AddStringToObject(object, "port", site_info[i].port);
            cJSON_AddStringToObject(object, "service_type", site_info[i].service_type);
            /* 0 未知 1 对外站点 2 对内站点 */
            cJSON_AddStringToObject(object, "port_status", site_info[i].port_status);
            /* 执行到此，表明是中间件的进程在运行，0 未知 1 正在运行 2 已停止
               暂时不检测已停止 */
            cJSON_AddStringToObject(object, "run_status", "1");
        }
    }

    return NULL;
}
void *sys_web_site_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

////////////////////////////////////////////////////////////////
///////////          web  middler                    ///////////
////////////////////////////////////////////////////////////////
#define MID_APACHE      0
#define MID_NGINX       1
#define MID_TOMCAT      2
#define MID_JBOSS       3
#define MID_WEBLOGIC    4
#define MID_JETTY       5
#define MID_WEBSPHERE   6
#define MID_WILDFLY     7
#define MID_MAX         8

typedef struct _midd_info
{
    char install_path[PATH_MAX];   // 安装路径
    char conf_path[PATH_MAX];      // 配置文件
    char access_path[PATH_MAX];    // 访问路径
    char name[64];
    char version[64];
    char type[64];
    char pid[32];
    char user[32];
    int midd_type;
    int once;
} midd_t;

/* Apache/Tomcat/Nginx/Jboss/Weblogic/Jetty/WebSphere/Wildfly */
static midd_t midd_set[MID_MAX];

static cJSON *compile_middler_cjson(const midd_t * info)
{
    cJSON *object = cJSON_CreateObject();

    if (info == NULL) return object;

    cJSON_AddStringToObject(object, "middleware_name", info->name);
    cJSON_AddStringToObject(object, "middleware_version", info->version);
    cJSON_AddStringToObject(object, "middleware_install_path", info->install_path);
    cJSON_AddStringToObject(object, "conf_file_path", info->conf_path);
    cJSON_AddStringToObject(object, "middleware_type", info->type);

    return object;
}
#ifdef SNIPER_FOR_DEBIAN
static char *get_tomcat_install_path()
{
    char path[PATH_MAX];
    char full_path[PATH_MAX];
    DIR *dirp = NULL;
    struct dirent *iter_ent = NULL;
    char *ret = NULL;
    char *default_path = "/usr/share/maven-repo/org/apache/tomcat/tomcat-catalina";

    if (is_dir(default_path) != 0) {
        return NULL;
    }

    dirp = opendir(default_path);

    if (!dirp) {
        return NULL;
    }

    while ((iter_ent = readdir(dirp))) {
        if (strncmp(iter_ent->d_name, ".", 1) == 0 || strncmp(iter_ent->d_name, "..", 2) == 0) {
            continue;
        }
        DIR *sub_dirp = NULL;
        struct dirent *sub_iter_ent = NULL;
        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/%s", default_path, iter_ent->d_name);
        sub_dirp = opendir(path);
        if (sub_dirp) {
            while ((sub_iter_ent = readdir(sub_dirp))) {
                if (strncmp(sub_iter_ent->d_name, ".", 1) == 0 || strncmp(sub_iter_ent->d_name, "..", 2) == 0) {
                    continue;
                }
                int len = strlen(sub_iter_ent->d_name);
                char *tmp = sub_iter_ent->d_name;
                if (len) {
                    tmp += len -4;
                    if (strncmp(tmp, ".jar", 4) != 0) {
                        continue;
                    }
                } else {
                    continue;
                }
                memset(full_path, 0x00, sizeof(full_path));
                snprintf(full_path, sizeof(full_path), "%s/%s", path, sub_iter_ent->d_name);
                ret = full_path;
                break;
            }
        }
        closedir(sub_dirp);
        break;
    }
    closedir(dirp);

    if (ret) {
        return strdup(ret);
    }
    return NULL;
}
static char *get_tomcat_conf_path()
{
    char path[PATH_MAX];
    char full_path[PATH_MAX];
    DIR *dirp = NULL;
    struct dirent *iter_ent = NULL;
    char *ret = NULL;
    char *default_path = "/var/lib";

    if (is_dir(default_path) != 0) {
        return NULL;
    }

    dirp = opendir(default_path);

    if (!dirp) {
        return NULL;
    }

    while ((iter_ent = readdir(dirp))) {
        if (strncmp(iter_ent->d_name, ".", 1) == 0 || strncmp(iter_ent->d_name, "..", 2) == 0) {
            continue;
        }
        if (strncmp(iter_ent->d_name, "tomcat", 6) != 0) {
            continue;
        }
        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/%s", default_path, iter_ent->d_name);
        ret = path;
        break;
    }
    closedir(dirp);

    if (ret) {
        return strdup(ret);
    }
    return NULL;
}
#endif
/**************************************************************************************************
 * 函数名: get_tomcat_info
 * 作用: 获取tomcat中间件的信息，版本，配置文件名，安装路径，类型(即nginx)
 * 输入: pid           进程名
 *      process_path  进程路径
 *      tomcat        tomcat中间件结构体
 * 输出: tomcat中间件Json数据
 * 返回值: 成功返回，tomcat中间件相关信息的Json数据
 *        失败返回，NULL
 * 其它: 根据进程名确定为tomcat中间件的进程
 *      默认安装进程参数
*         Centos
 *        tomcat /usr/lib/jvm/jre/bin/java
 *        -Djavax.sql.DataSource.Factory=org.apache.commons.dbcp.BasicDataSourceFactory
 *        -classpath /usr/share/tomcat/bin/bootstrap.jar:/usr/share/tomcat/bin/tomcat-juli.jar:/usr/share/java/commons-daemon.jar 
 *        -Dcatalina.base=/usr/share/tomcat 
 *        -Dcatalina.home=/usr/share/tomcat 
 *        -Djava.endorsed.dirs=
 *        -Djava.io.tmpdir=/var/cache/tomcat/temp 
 *        -Djava.util.logging.config.file=/usr/share/tomcat/conf/logging.properties 
 *        -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager org.apache.catalina.startup.Bootstrap start
 *        Ubuntu
 *        tomcat8 /usr/lib/jvm/default-java/bin/java 
 *        -Djava.util.logging.config.file=/var/lib/tomcat8/conf/logging.properties
 *        -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager 
 *        -Djava.awt.headless=true -Xmx128m -XX:+UseConcMarkSweepGC 
 *        -Djava.endorsed.dirs=/usr/share/tomcat8/endorsed 
 *        -classpath /usr/share/tomcat8/bin/bootstrap.jar:/usr/share/tomcat8/bin/tomcat-juli.jar 
 *        -Dcatalina.base=/var/lib/tomcat8 
 *        -Dcatalina.home=/usr/share/tomcat8 
 *        -Djava.io.tmpdir=/tmp/tomcat8-tomcat8-tmp org.apache.catalina.startup.Bootstrap start
 *      自定义安装目录进程参数
 *        root  /usr/bin/java
 *        -Djava.util.logging.config.file=/root/tomcat_test/apache-tomcat-8.5.72/conf/logging.properties 
 *        -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager
 *        -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources 
 *        -Dorg.apache.catalina.security.SecurityListener.UMASK=0027
 *        -Dignore.endorsed.dirs=
 *        -classpath /root/tomcat_test/apache-tomcat-8.5.72/bin/bootstrap.jar:/root/tomcat_test/apache-tomcat-8.5.72/bin/tomcat-juli.jar 
 *        -Dcatalina.base=/root/tomcat_test/apache-tomcat-8.5.72 
 *        -Dcatalina.home=/root/tomcat_test/apache-tomcat-8.5.72 
 *        -Djava.io.tmpdir=/root/tomcat_test/apache-tomcat-8.5.72/temp org.apache.catalina.startup.Bootstrap star
 *      目前以config.file为条件，获取安装路径，以及配置文件所在目录
 *      获取版本信息，默认安装以/usr/share/java/tomcat/catalina.jar获取
 *                 自定义安装以-Dcatalina.base=参数路径加 /lib/catalina.jar
**************************************************************************************************/
static cJSON *get_tomcat_info(const char *pid, const char *process_path, const char *cmd_line, midd_t *tomcat)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char *tmp = NULL;
    char version_cmd[PATH_MAX];
    int len = 0;
    int once = 0;

    if (pid == NULL || process_path == NULL || cmd_line == NULL || tomcat == NULL) {
        tomcat->once = -1;
        return cJSON_CreateObject();
    }

    /* name */
    snprintf(tomcat->name, sizeof(tomcat->name), "%s", "tomcat");


    tmp = strstr(cmd_line, "-Dcatalina.base");
    if (!tmp) { // 参数可能不全，去/porc/pid/cmdline里再取一遍
        tmp =get_cmd_line_by_pid(pid);
        if (tmp) {
            memset (line, 0x00, sizeof(line));
            snprintf(line, sizeof(line), "%s", tmp);
            free(tmp);
            tmp = NULL;
        } else {
            return NULL;
        }
        tmp = strstr(line, "-Dcatalina.base");
        if (!tmp) {
            return NULL;
        }
    }
    tmp += 16;

    /* install path */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", tmp);
    tmp = strchr(path, ' ');
    if (tmp) {
        *tmp = '\0';
    }
    snprintf(tomcat->install_path, sizeof(tomcat->install_path), "%s", path);
    if (is_dir(tomcat->install_path) != 0) { // 无效安装目录
        return NULL;
    }

    memset(version_cmd, 0x00, sizeof(version_cmd));
#ifdef SNIPER_FOR_DEBIAN
    if (strncmp(tomcat->install_path, "/usr/share/tomcat", 17) == 0) { // 视为默认安装版本不一定是多少，因此匹配前面路径
        char *tomcat_path = get_tomcat_install_path();

        if (tomcat_path) {
            snprintf(version_cmd, sizeof(version_cmd), "%s", tomcat_path);
            free(tomcat_path);
        } else {
            return NULL;
        }
        snprintf(tomcat->conf_path, sizeof(tomcat->conf_path), "%s", "/etc/tomcat8/server.xml");
#else
    if (strcmp(tomcat->install_path, "/usr/share/tomcat") == 0) { // 视为默认安装,Centos下目录不带版本号
        snprintf(version_cmd, sizeof(version_cmd), "%s", "/usr/share/java/tomcat/catalina.jar");
#endif
    } else {
        snprintf(version_cmd, sizeof(version_cmd), "%s%s", tomcat->install_path, "/lib/catalina.jar");
    }

try_again:
    /* version */
    if (is_file(version_cmd) == 0) {
        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "java -cp %s org.apache.catalina.util.ServerInfo", version_cmd);
        if (popen_filter_one_keystr(path, NULL, line, sizeof(line)) != 0) {
            // snprintf(tomcat->version, sizeof(tomcat->version), "%s", "None");
            return NULL;
        } else {
            char *tmp = strchr(line, ':');
            if (tmp) {
                tmp += 2;
                len = strlen(tmp);
                if (tmp[len-1] == '\n') tmp[len-1] = '\0';
                snprintf(tomcat->version, sizeof(tomcat->version), "%s", tmp);
            }
            else {
                snprintf(tomcat->version, sizeof(tomcat->version), "%s", line);
            }
        }
    } else {
        if (once) {
            elog("Detect tomcat version again failed :%s\n", path);
            return NULL;
        }
        /* 可能是老版本的tomcat,目录中多了一层server */
        tmp = strstr(version_cmd, "/lib/catalina.jar");
        if (tmp) {
            *tmp = '\0';
            len = strlen(version_cmd);
            snprintf(version_cmd+len, sizeof(version_cmd)-len, "%s", "/server/lib/catalina.jar");
            once = 1;
            goto try_again;
        }
        elog("Detect tomcat version failed :%s\n", path);
        return NULL;
    }

    /* config path */
#ifdef SNIPER_FOR_DEBIAN
    if (!tomcat->conf_path[0]) { // 配置文件为空,不是默认安装目录
        snprintf(tomcat->conf_path, sizeof(tomcat->conf_path), "%s/conf/server.xml", tomcat->install_path);
        if (is_file(tomcat->conf_path) != 0) {
            snprintf(tomcat->conf_path, sizeof(tomcat->conf_path), "%s", "None");
            tomcat->conf_path[4] = '\0';
        }
    }
#else
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s/conf/server.xml", tomcat->install_path);
    if (is_file(path) == 0) {
        snprintf(tomcat->conf_path, sizeof(tomcat->conf_path), "%s", path);
    } else {
        elog("Detect tomcat conf file failed\n");
        return NULL;
    }
#endif

    /* type */
    snprintf(tomcat->type, sizeof(tomcat->type), "%s", "tomcat");
    tomcat->midd_type = MID_TOMCAT;
    tomcat->once = 1;

    return compile_middler_cjson(tomcat);
}

/**************************************************************************************************
 * 函数名: get_nginx_info
 * 作用: 获取nginx中间件的信息，版本，配置文件名，安装路径，类型(即nginx)
 * 输入: pid           进程名
 *      process_path  进程路径
 *      cmd_line      进程命令行参数
 *      nginx         nginx中间件结构体
 * 输出: nginx中间件Json数据
 * 返回值: 成功返回，nginx中间件相关信息的Json数据
 *        失败返回，NULL
 * 其它: 根据进程名确定为nginx中间件的进程
 *      版本，通过cmdline绝对路径，执行/path/nginx -v获取版本信息
 *      安装路径，通过参数process_path获取
 *      配置文件，如果nginx有-c的参数则获取-c后面的参数即为配置文件路径，否则查找/etc/nginx/nginx.conf文件
**************************************************************************************************/
static cJSON *get_nginx_info(const char *pid, const char *process_path, const char *cmd_line, midd_t *nginx)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    const char *default_conf = "/etc/nginx/nginx.conf";
    int len = 0;
    char *tmp = NULL;

    if (pid == NULL || process_path == NULL || cmd_line == NULL || nginx == NULL) {
        nginx->once = -1;
        return cJSON_CreateObject();
    }

    /* name */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", process_path);
    snprintf(nginx->name, sizeof(nginx->name), "%s", basename(path));

    /* version */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s -V 2>&1", process_path);
    if (popen_filter_one_keystr(path, ":", line, sizeof(line)) != 0) {
        snprintf(nginx->version, sizeof(nginx->version), "%s", "None");
    }
    else {
        tmp = strchr(line, ':');
        if (tmp) {
            tmp += 2;
            len = strlen(tmp);
            if (tmp[len-1] == '\n') tmp[len-1] = '\0';
            snprintf(nginx->version, sizeof(nginx->version), "%s", tmp);
        }
        else {
            snprintf(nginx->version, sizeof(nginx->version), "%s", line);
        }
    }

    /* install path */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", process_path);
    snprintf(nginx->install_path, sizeof(nginx->install_path), "%s", dirname(path));

    /* config path */
    memset(path, 0x00, sizeof(path));
    tmp = strstr(cmd_line, "-c");
    if (tmp) {
        tmp += 2;
        while (*tmp == ' ') {
            tmp ++;
        }
        snprintf(path, sizeof(path), "%s", tmp);
        // 配置文件名不一定是ngin.conf，但是空格可以判定-c参数指定的文件结束
        tmp = strchr(path, ' ');
        if (tmp) {
            *tmp = '\0';
        }
    }
    if (path[0] && is_file(path) == 0) {
        snprintf(nginx->conf_path, sizeof(nginx->conf_path), "%s", path);
    }
    else {
        if (is_file(default_conf) == 0) {
            snprintf(nginx->conf_path, sizeof(nginx->conf_path), "%s", default_conf);
        } else {
            snprintf(nginx->conf_path, sizeof(nginx->conf_path), "%s", "None");
        }
    }

    /* type */
    snprintf(nginx->type, sizeof(nginx->type), "%s", "nginx");
    nginx->midd_type = MID_NGINX;
    nginx->once = 1;

    return compile_middler_cjson(nginx);
}

/**************************************************************************************************
 * 函数名: get_apache_info
 * 作用: 获取apache中间件的信息，版本，配置文件名，安装路径，类型(即apache)
 * 输入: pid           进程名
 *      process_path  进程路径
 *      cmdline       进程启动参数
 *      appache       apache中间件结构体
 * 输出: apache中间件Json信息
 * 返回值: 成功返回，apache中间件相关信息的Json数据
 *        失败返回，NULL
 * 其它: 根据进程名确定为apache中间件的进程
 *      版本，通过/proc/pid/cmdline拿到绝对路径，通过执行apache/httpd -v获取版本信息
 *      安装路径，通过参数process_path获取
 *      配置文件，查找固定目录/etc/apache2/apache2.conf(Ubuntu)或者/etc/httpd/conf/httpd.conf(Centos)
**************************************************************************************************/
static cJSON *get_apache_info(const char *pid, const char *process_path, const char *cmd_line, midd_t *apache)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char *tmp = NULL;
    int len = 0;

    if (pid == NULL || process_path == NULL || cmd_line == NULL || apache == NULL) {
        apache->once = -1;
        return cJSON_CreateObject();
    }

    /* name */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", process_path);
    snprintf(apache->name, sizeof(apache->name), "%s", basename(path));

    /* version */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    if (return_file_first_line(path, line, sizeof(line)) != 0) {
        snprintf(apache->version, sizeof(apache->version), "%s", "None");
    }
    else {
        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s -v", line);
        if (popen_filter_one_keystr(path, NULL, line, sizeof(line)) != 0) {
            snprintf(apache->version, sizeof(apache->version), "%s", "None");
        }
        else {
            char *tmp = strchr(line, ':');
            if (tmp) {
                tmp += 2;
                len = strlen(tmp);
                if (tmp[len-1] == '\n') tmp[len-1] = '\0';
                snprintf(apache->version, sizeof(apache->version), "%s", tmp);
            }
            else {
                snprintf(apache->version, sizeof(apache->version), "%s", line);
            }
        }
    }

    /* install path */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", process_path);
    snprintf(apache->install_path, sizeof(apache->install_path), "%s", dirname(path));

    /* config path */
    memset(path, 0x00, sizeof(path));
    // 指定配置文件/usr/local/apache2/bin/httpd -k start -f /usr/local/apache2/conf/http.conf 
    tmp = strstr(cmd_line, "-f");
    if (tmp) {
        tmp += 2;
        while (*tmp == ' ') {
            tmp ++;
        }
        snprintf(path, sizeof(path), "%s", tmp);
        tmp = strchr(path, ' ');
        if (tmp) {
            *tmp = '\0';
        }
        // apache配置文件路径
        if (is_file(path) == 0) {
            snprintf(apache->conf_path, sizeof(apache->conf_path), "%s", path);
        } else {
            apache->conf_path[0] = '\0';
        }
    }

    if (!apache->conf_path[0]) { // 没找到，查找默认配置文件路径
#ifdef SNIPER_FOR_DEBIAN
        if (is_file("/etc/apache2/apache2.conf") == 0) {
            snprintf(apache->conf_path, sizeof(apache->conf_path), "%s", "/etc/apache2/apache2.conf");
#else
        if (is_file("/etc/httpd/conf/httpd.conf") == 0) {
            snprintf(apache->conf_path, sizeof(apache->conf_path), "%s", "/etc/httpd/conf/httpd.conf");
#endif
        }
        else {
            snprintf(apache->conf_path, sizeof(apache->conf_path), "%s", "None");
        }
    }

    /* type */
    snprintf(apache->type, sizeof(apache->type), "%s", "apache");
    apache->midd_type = MID_APACHE;
    apache->once = 1;

    return compile_middler_cjson(apache);
}

/**************************************************************************************************
 * 函数名: get_weblogic_info
 * 作用: 获取weblogic中间件的信息，版本，配置文件名，安装路径，类型(即nginx)
 * 输入: pid           进程名
 *      process_path  进程路径
 *      weblogic      weblogic中间件结构体
 * 输出: weblogic中间件Json数据
 * 返回值: 成功返回，weblogic中间件相关信息的Json数据
 *        失败返回，NULL
 * 其它: 根据进程名确定为weblogic中间件的进程
 *      版本，通过cmdline获取weblogic路径，查找文件inventory/registry.xml中version=的关键字得到版本信息
 *      安装路径，通过参数cmdline参数-D获取
 *      配置文件，安装目录下/wlserver/common/bin/config.sh为配置文件
**************************************************************************************************/
static cJSON *get_weblogic_info(const char *pid, const char *process_path, midd_t *weblogic)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char install_path[PATH_MAX];
    char conf_path[PATH_MAX];
    int len = 0;
    int fd = 0;
    unsigned char *tmp = NULL;
    unsigned char *end = NULL;

    if (pid == NULL || process_path == NULL || weblogic == NULL) {
        weblogic->once = -1;
        return cJSON_CreateObject();
    }

    /* name */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", process_path);
    snprintf(weblogic->name, sizeof(weblogic->name), "%s", "weblogic");

    /* get cmdline */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    memset(install_path, 0x00, sizeof(install_path));
    memset(path, 0x00, sizeof(path));
    tmp = strstr(line, "-D");
    if (tmp) {
        tmp = strstr(tmp, "=");
        if (tmp) {
            ++tmp;
            snprintf(install_path, sizeof(install_path), "%s", tmp);
            tmp = strstr(install_path, "Oracle_Home");
            if (tmp) {
                *(tmp+11) = '\0';
                snprintf(path, sizeof(path), "%s", install_path);
            } else {
                tmp = strchr(install_path, ' ');
                if (tmp) {
                    *tmp = '\0';
                }
            }
        } else {
            // snprintf(install_path, sizeof(install_path), "%s", "None");
            return NULL;
        }
    } else {
        // snprintf(install_path, sizeof(install_path), "%s", "None");
        return NULL;
    }

    /* version */
    if (path[0]) {
        snprintf(conf_path, sizeof(conf_path), "%s/%s", path, "/inventory/registry.xml");
        if (is_file(conf_path) == 0) {
            if (find_key_from_file(conf_path, "WebLogic", line, sizeof(line), 1) == 0) {
                char *tmp = strstr(line, "version=\"");
                if (tmp) {
                    tmp += 9;
                    len = strlen(tmp);
                    if (tmp[len-1] == '\n') tmp[len-1] = '\0';
                    snprintf(weblogic->version, sizeof(weblogic->version), "%s", tmp);
                    tmp = strchr(weblogic->version, '\"');
                    if (tmp) {
                        *tmp = '\0';
                    }
                }
                else {
                    // snprintf(weblogic->version, sizeof(weblogic->version), "%s", "None");
                    return NULL;
                }
            }
        } else {
            // snprintf(weblogic->version, sizeof(weblogic->version), "%s", "None");
            return NULL;
        }
    }

    /* install path */
    if (is_dir(install_path) == 0) {
        snprintf(weblogic->install_path, sizeof(weblogic->install_path), "%s", install_path);
    } else {
        // snprintf(weblogic->install_path, sizeof(weblogic->install_path), "%s", "None");
        return NULL;
    }

    /* config path */
    snprintf(weblogic->conf_path, sizeof(weblogic->conf_path), "%s/wlserver/common/bin/config.sh", path);
    if (is_file(weblogic->conf_path) != 0) {
        memset(weblogic->conf_path, 0x00, sizeof(weblogic->conf_path));
        // snprintf(weblogic->conf_path, sizeof(weblogic->conf_path), "%s", "None");
        return NULL;
    }

    /* type */
    snprintf(weblogic->type, sizeof(weblogic->type), "%s", "weblogic");
    weblogic->midd_type = MID_WEBLOGIC;
    weblogic->once = 1;

    return compile_middler_cjson(weblogic);
}

/**************************************************************************************************
 * 函数名: get_wildfly_info
 * 作用: 获取wildfly中间件的信息，版本，配置文件名，安装路径，类型
 * 输入: pid           进程名
 *      process_path  进程路径
 *      wildfly       wildfly中间件结构体
 * 输出: wildfly中间件Json数据
 * 返回值: 成功返回，wildfly中间件相关信息的Json数据
 *        失败返回，NULL
 * 其它: 根据进程名确定为wildfly中间件的进程
 *      版本，通过cmdline获取wildfly路径，执行命令standalone.sh -v得到版本信息
 *      安装路径，通过参数cmdline参数-Djboss.home.dir=获取
 *      配置文件，安装目录下standalone/configuration/standalone.xml为配置文件
 * 
 * 默认进程用户 wildfly
 * cmdline
 * java -D[Standalone] -server -Xms64m -Xmx512m -XX:MetaspaceSize=96M 
 * -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true -Djboss.modules.system.pkgs=org.jboss.byteman 
 * -Djava.awt.headless=true -Dorg.jboss.boot.log.file=/opt/wildfly/standalone/log/server.log 
 * -Dlogging.configuration=file:/opt/wildfly/standalone/configuration/logging.properties 
 * -jar /opt/wildfly/jboss-modules.jar -mp /opt/wildfly/modules org.jboss.as.standalone 
 * 找下面这行，即安装目录
 * -Djboss.home.dir=/opt/wildfly 
 * -Djboss.server.base.dir=/opt/wildfly/standalone -c standalone.xml -b 0.0.0.0
**************************************************************************************************/
static cJSON *get_wildfly_info(const char *pid, const char *process_path, midd_t *wildfly)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char install_path[PATH_MAX];
    char cmd[PATH_MAX];
    int len = 0;
    int fd = 0;
    unsigned char *tmp = NULL;
    unsigned char *end = NULL;

    if (pid == NULL || process_path == NULL || wildfly == NULL) {
        wildfly->once = -1;
        return cJSON_CreateObject();
    }

    /* name */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", process_path);
    snprintf(wildfly->name, sizeof(wildfly->name), "%s", "wildfly");

    /* get cmdline */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    memset(install_path, 0x00, sizeof(install_path));
    memset(path, 0x00, sizeof(path));
    tmp = strstr(line, "-Djboss.home.dir");
    if (tmp) {
        tmp = strstr(tmp, "=");
        if (tmp) {
            ++tmp;
            snprintf(install_path, sizeof(install_path), "%s", tmp);
            tmp = strchr(install_path, ' ');
            if (tmp) {
                *tmp = '\0';
            }
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }

    /* install path */
    if (is_dir(install_path) == 0) {
        snprintf(wildfly->install_path, sizeof(wildfly->install_path), "%s", install_path);
    } else {
        return NULL;
    }

    /* version */
    if (install_path[0]) {
        memset (cmd, 0x00, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "%s/%s", install_path, "/bin/standalone.sh -v");
        if (popen_filter_one_keystr(cmd, "JBoss Modules version", line, sizeof(line)) == 0) {
            tmp = strstr(line, "JBoss Modules version");
            if (tmp) {
                tmp += 21;
                if (*tmp == ' ') {
                    ++ tmp;
                }
                snprintf(wildfly->version, sizeof(wildfly->version), "%s", tmp);
                len = strlen(wildfly->version);
                if (wildfly->version[len-1] == '\n') {
                    wildfly->version[len-1] = '\0';
                }
            } else {
                return NULL;
            }
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }

    /* config path */
    snprintf(wildfly->conf_path, sizeof(wildfly->conf_path), 
            "%s/standalone/configuration/standalone.xml", wildfly->install_path);
    if (is_file(wildfly->conf_path) != 0) {
        memset(wildfly->conf_path, 0x00, sizeof(wildfly->conf_path));
        return NULL;
    }

    /* type */
    snprintf(wildfly->type, sizeof(wildfly->type), "%s", "wildfly");
    wildfly->midd_type = MID_WILDFLY;
    wildfly->once = 1;

    return compile_middler_cjson(wildfly);
}

/**************************************************************************************************
 * 函数名: get_websphere_info
 * 作用: 获取websphere中间件的信息，版本，配置文件名，安装路径，类型
 * 输入: pid           进程名
 *      process_path  进程路径
 *      websphere     websphere中间件结构体
 * 输出: websphere中间件Json数据
 * 返回值: 成功返回，websphere中间件相关信息的Json数据
 *        失败返回，NULL
 * 其它: 根据进程名确定为wildfly中间件的进程
 *      版本，通过cmdline获取wildfly路径，执行命令standalone.sh -v得到版本信息
 *      安装路径，通过参数cmdline参数-Djboss.home.dir=获取
 *      配置文件，安装目录下standalone/configuration/standalone.xml为配置文件
 * 获取cmdline，匹配-Dosgi.install.area等于号后面即安装路径
 * /opt/IBM/WebSphere/AppServer/java/8.0/bin/java -Dosgi.install.area=/opt/IBM/WebSphere/AppServer 
 * -Dosgi.configuration.area=/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/servers/server1/configuration 
 * -Dws.ext.dirs=/opt/IBM/WebSphere/AppServer/java/8.0/lib:/opt/IBM/WebSphere/AppServer/classes:/opt/IBM/WebSphere/AppServer/lib:
 * /opt/IBM/WebSphere/AppServer/installedChannels:/opt/IBM/WebSphere/AppServer/lib/ext:/opt/IBM/WebSphere/AppServer/web/help:
 * /opt/IBM/WebSphere/AppServer/deploytool/itp/plugins/com.ibm.etools.ejbdeploy/runtime 
 * -Djava.ext.dirs=/opt/IBM/WebSphere/AppServer/javaext:/opt/IBM/WebSphere/AppServer/java/8.0/lib/ext:/opt/IBM/WebSphere/AppServer/java/8.0/jre/lib/ext 
 * -Djava.endorsed.dirs=/opt/IBM/WebSphere/AppServer/endorsed_apis:/opt/IBM/WebSphere/AppServer/java/8.0/jre/lib/endorsed 
 * -Dwas.install.root=/opt/IBM/WebSphere/AppServer 
 * -Djava.util.logging.manager=com.ibm.ws.bootstrap.WsLogManager -Djava.util.logging.configureByServer=true 
 * -classpath /opt/IBM/WebSphere/AppServer/profiles/AppSrv01/properties
 * :/opt/IBM/WebSphere/AppServer/properties:/opt/IBM/WebSphere/AppServer/lib/startup.jar:/opt/IBM/WebSphere/AppServer/lib/bootstrap.jar:
 * /opt/IBM/WebSphere/AppServer/java/8.0/lib/tools.jar:/opt/IBM/WebSphere/AppServer/lib/lmproxy.jar:/opt/IBM/WebSphere/AppServer/lib/urlprotocols.jar 
 * -Duser.install.root=/opt/IBM/WebSphere/AppServer/profiles/AppSrv01 com.ibm.ws.bootstrap.WSLauncher com.ibm.ws.management.tools.WsServerLauncher 
 * /opt/IBM/WebSphere/AppServer/profiles/AppSrv01/config DESKTOP-K76M8BRNode01Cell DESKTOP-K76M8BRNode01 server1 -profileName AppSrv01
**************************************************************************************************/

static cJSON *get_websphere_info(const char *pid, const char *process_path, midd_t *websphere)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char install_path[PATH_MAX];
    char cmd[PATH_MAX];
    int len = 0;
    int fd = 0;
    FILE *fp = NULL;
    unsigned char *tmp = NULL;
    unsigned char *end = NULL;

    if (pid == NULL || process_path == NULL || websphere == NULL) {
        websphere->once = -1;
        return cJSON_CreateObject();
    }

    /* name */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", process_path);
    snprintf(websphere->name, sizeof(websphere->name), "%s", "websphere");

    /* get cmdline */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    memset(install_path, 0x00, sizeof(install_path));
    memset(path, 0x00, sizeof(path));
    tmp = strstr(line, "-Dosgi.install.area");
    if (tmp) {
        tmp = strstr(tmp, "=");
        if (tmp) {
            ++tmp;
            snprintf(install_path, sizeof(install_path), "%s", tmp);
            tmp = strchr(install_path, ' ');
            if (tmp) {
                *tmp = '\0';
            }
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }

    /* install path */
    if (is_dir(install_path) == 0) {
        snprintf(websphere->install_path, sizeof(websphere->install_path), "%s", install_path);
    } else {
        return NULL;
    }

    /* version */
    if (!install_path[0]) {
        return NULL;
    }
    memset (cmd, 0x00, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "%s/%s", install_path, "/bin/versionInfo.sh");

    if ((fp = popen(cmd, "r")) == NULL) {
        return NULL;
    }
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        /* 版本信息，版本后面的空格是为了排除结果中带有 版本目录 的行
         * Version    8.5.5.0
         * 版本       8.5.5.0
         */
        if (strstr(line, "Version    ") || strstr(line, "版本  ")) {
            tmp = strchr(line, ' ');
            delete_tailspace(tmp);
            tmp = skip_headspace(tmp);
            snprintf(websphere->version, sizeof(websphere->version), "%s", tmp);
            break;
        }
    }
    pclose(fp);

    if (!websphere->version[0]) {
        return NULL;
    }

    /* config path */
    snprintf(websphere->conf_path, sizeof(websphere->conf_path), "%s/profiles", install_path);
    if (is_dir(websphere->conf_path) != 0) {
        memset(websphere->conf_path, 0x00, sizeof(websphere->conf_path));
        return NULL;
    }

    /* type */
    snprintf(websphere->type, sizeof(websphere->type), "%s", "wildfly");
    websphere->midd_type = MID_WEBSPHERE;
    websphere->once = 1;

    return compile_middler_cjson(websphere);
}

static int init_middler_set()
{
    int i = 0;

    memset(midd_set, 0x00, sizeof(midd_t)*MID_MAX);

    for (; i<MID_MAX; i++){
        midd_set[i].midd_type = -1;
    }

    return 0;
}

/* 此处查询语句目前只支持apache, tomcat, nginx和PHP中间件 */
#ifdef SNIPER_FOR_DEBIAN
static const char *query_web_middler = "select pid,name,user,cmdline from sys_process where \
                                        name like '%/php-fpm' or name like '%/apache2' or name like '%/nginx' \
                                        or user like '\%tomcat\%' or name like '%/java' or name like '%/jsvc';";
#else
static const char *query_web_middler = "select pid,name,user,cmdline from sys_process where \
                                        name like '%/php-fpm' or name like '%/httpd' or name like '%/nginx' \
                                        or user like '\%tomcat\%' or name like '%/java' or name like '%/httpd-prefork' \
                                        or name like '%/jsvc';";
#endif

/* JSON web_middler
 * 检测web中间件
 * 返回Json数据格式
 * apache与tomcat的关系
 * 一般使用apache+tomcat的话，apache只是作为一个转发，对jsp的处理是由tomcat来处理的。
 * apache可以支持php\cgi\perl,但是要使用java的话，需要tomcat在apache后台支撑，将java请求由apache转发给tomcat处理。
 * apache是web服务器,Tomcat是应用（java）服务器，它只是一个servlet(jsp也翻译成servlet)容器，可以认为是apache的扩展，但是可以独立于apache运行。
 */
void *sys_web_middler_info(sys_info_t *data)
{
    char midd_path[PATH_MAX];
    sqlite3_stmt * stmt = NULL;
    const char *zTail;
    int ret = 0;

    if (data->object == NULL || data->db == NULL) return NULL;

    init_middler_set();

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, query_web_middler, -1, &stmt, &zTail);
    if (ret !=SQLITE_OK){
        elog("No process info\n");
    }
    else {
        data->ret = (void*)stmt;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *pid = sqlite3_column_text(stmt, 0);
        const char *process_path = sqlite3_column_text(stmt, 1);
        const char *process_user = sqlite3_column_text(stmt, 2);
        const char *cmd_line = sqlite3_column_text(stmt, 3);

        memset(midd_path, 0x00, sizeof(midd_path));
        snprintf(midd_path, sizeof(midd_path), "%s", process_path);
        if (strncmp(basename(midd_path), "apache2", 7) == 0 /* apache */
            || strncmp(basename(midd_path), "httpd", 5) == 0
            || strncmp(basename(midd_path), "httpd-prefork", 13) == 0) { /* apache */
            midd_t *apache = &midd_set[MID_APACHE];
            if (apache->once == 0) {
                dlog("apache, %s, %s, %s\n", pid, process_path, process_user);
                snprintf(apache->user, sizeof(apache->user), "%s", process_user);
                snprintf(apache->pid, sizeof(apache->pid), "%s", pid);
                cJSON_AddItemToArray(data->object, get_apache_info(pid, process_path, cmd_line, apache));
            }
        } else if (strncmp(basename(midd_path), "nginx", 5) == 0
                    && strncmp(process_user, "root", 4) == 0) { /* nginx */
            midd_t *nginx = &midd_set[MID_NGINX];
            if (nginx->once == 0) {
                dlog("nginx, %s, %s, %s\n", pid, process_path, process_user);
                snprintf(nginx->user, sizeof(nginx->user), "%s", process_user);
                snprintf(nginx->pid, sizeof(nginx->pid), "%s", pid);
                cJSON_AddItemToArray(data->object, get_nginx_info(pid, process_path, cmd_line, nginx));
            }
        } 
        /* java的进程每个都单独if判断，否则不能完全匹配一遍 */
        if (strncmp(basename(midd_path), "java", 4) == 0 
                    || strncmp(basename(midd_path), "jsvc", 4) == 0  //jsvc或jsvc.exec
                    || strncmp(process_user, "tomcat", 6) == 0) { /* tomcat */
            midd_t *tomcat = &midd_set[MID_TOMCAT];
            if (tomcat->once == 0) {
                dlog("tomcat, %s, %s, %s\n", pid, process_path, process_user);
                snprintf(tomcat->user, sizeof(tomcat->user), "%s", process_user);
                snprintf(tomcat->pid, sizeof(tomcat->pid), "%s", pid);
                cJSON_AddItemToArray(data->object, get_tomcat_info(pid, process_path, cmd_line, tomcat));
            }
        }
        if (strncmp(basename(midd_path), "java", 4) == 0 
                    || strncmp(process_user, "oracle", 6) == 0) {
            midd_t *weblogic = &midd_set[MID_WEBLOGIC];
            if (weblogic->once == 0) {
                dlog("weblogic, %s, %s, %s\n", pid, process_path, process_user);
                snprintf(weblogic->user, sizeof(weblogic->user), "%s", process_user);
                snprintf(weblogic->pid, sizeof(weblogic->pid), "%s", pid);
                cJSON_AddItemToArray(data->object, get_weblogic_info(pid, process_path, weblogic));
            }
        }
        if (strncmp(basename(midd_path), "java", 4) == 0
                    || strncmp(process_user, "wildfly", 7) == 0) { /* wildfly以前叫JBoss AS */
            midd_t *wildfly = &midd_set[MID_JBOSS];
            if (wildfly->once == 0) {
                dlog("JBoss, %s, %s, %s\n", pid, process_path, process_user);
                snprintf(wildfly->user, sizeof(wildfly->user), "%s", process_user);
                snprintf(wildfly->pid, sizeof(wildfly->pid), "%s", pid);
                cJSON_AddItemToArray(data->object, get_wildfly_info(pid, process_path, wildfly));
            }
        }
        if (strncmp(basename(midd_path), "java", 4) == 0
                    || strncmp(process_user, "root", 9) == 0) { /* WebSphere */
            midd_t *websphere = &midd_set[MID_WEBSPHERE];
            if (websphere->once == 0) {
                dlog("WebSphere, %s, %s, %s\n", pid, process_path, process_user);
                snprintf(websphere->user, sizeof(websphere->user), "%s", process_user);
                snprintf(websphere->pid, sizeof(websphere->pid), "%s", pid);
                cJSON_AddItemToArray(data->object, get_websphere_info(pid, process_path, websphere));
            }
        }
        /* todo
         * JBoss/Jetty
         */
    }

    sqlite3_finalize(stmt);

    return NULL;
}
void *sys_web_middler_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

static int find_key_from_file(const char *file_path, 
            const char *key, char *buf, const unsigned buf_len, const int flag)
{
    FILE *fp = NULL;
    int ret = 0;
    int len = 0;

    if (file_path == NULL || buf == NULL || buf_len == 0) return -1;

    memset (buf, 0x00, buf_len);

    fp = fopen(file_path, "r");
    if (!fp) return -1;

    len = strlen(key);
    
    while (fgets(buf, buf_len-1, fp) != NULL) {
        if (flag) {
            if (strstr(buf, key)) break;
        }
        else {
            if (strncmp(buf, key, len) == 0) break;
        }
    }
    fclose(fp);

    return ret;
}

static int get_web_app_thinkphp(const char *app_path, const midd_t *mid, sys_info_t *data)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char app_name[64];
    char version[64];
    char language[32];
    char *name = "THINK_VERSION";
    char *tmp = NULL;
    int ret = 0;

    if (app_path == NULL || mid == NULL || data == NULL || data->object == NULL) {
        goto End;
    }

    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s/thinkphp/base.php", app_path);

    if (is_file(path) != 0) {
        goto End;
    }

    memset(app_name, 0x00, sizeof(app_name));
    snprintf(app_name, sizeof(app_name), "%s", "ThinkPHP");
    memset(language, 0x00, sizeof(language));
    snprintf(language, sizeof(language), "%s", "php");
    /* version */
    if (find_key_from_file(path, name, line, sizeof(line), 1) == 0) {
        tmp = strstr(line, name);
        if (tmp) {
            tmp += strlen("THINK_VERSION") + 2;
            tmp = strchr(tmp, '\'');
            if (tmp) {
                tmp ++;
                snprintf(version, sizeof(version), "%s", tmp);
                tmp = strchr(version, '\'');
                if (tmp) {
                    *tmp = '\0';
                }
            } else {
                snprintf(version, sizeof(version), "%s", "None");
            }
        } else {
            snprintf(version, sizeof(version), "%s", "None");
        }
    } else {
        snprintf(version, sizeof(version), "%s", "None");
    }
    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "app_name", app_name);
    cJSON_AddStringToObject(object, "app_path", app_path);
    cJSON_AddStringToObject(object, "service_type", mid->type);
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "language", language);
    cJSON_AddNumberToObject(object, "plugin_count", 0);
    cJSON_AddItemToArray(data->object, object);
    /* Web站点与Web应用部分数据来源相同 */
    snprintf(site_info[SITE_THINKPHP].home_dir, sizeof(site_info[SITE_THINKPHP].home_dir), "%s", app_path);
    snprintf(site_info[SITE_THINKPHP].run_user, sizeof(site_info[SITE_THINKPHP].run_user), "%s", mid->user);
    snprintf(site_info[SITE_THINKPHP].pid, sizeof(site_info[SITE_THINKPHP].pid), "%s", mid->pid);
    snprintf(site_info[SITE_THINKPHP].service_type, sizeof(site_info[SITE_THINKPHP].service_type), "%s", mid->type);
    supplement_apache_info(&site_info[SITE_THINKPHP]);
    site_info[SITE_THINKPHP].is_found = 1;

    return ret;
End:
    return -1;
}

static int get_apache_web_app(const midd_t *mid, sys_info_t *data)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    char app_name[64];
    char version[64];
    char language[32];
    DIR *dirp = NULL;
    struct dirent *iter_ent = NULL;
    char *tmp = NULL;
    int ret = 0;
    int i = 0;
    const char *app_path;

    if (mid == NULL || data == NULL || data->object == NULL) goto End;

    /* 有访问路径就用访问路径，没有的话使用默认路径 */
    if (mid->access_path[0]) {
        if (is_dir(mid->access_path) == 0) {
            app_path = mid->access_path;
        } else {
            app_path = "/var/www/html";
        }
    } else {
        app_path = "/var/www/html";
    }

    if (is_dir(app_path) != 0) goto End;

    dirp = opendir(app_path);
    if (!dirp) goto End;

    while ((iter_ent = readdir(dirp))) {
        /* WordPress */
        if (strncmp(iter_ent->d_name, "wp-config.php", 13) == 0 || 
           strncmp(iter_ent->d_name, "wordpress", 9) == 0) {
            char wordpress[] = "wordpress/";
            memset(path, 0x00, sizeof(path));
            snprintf(path, sizeof(path), "%s/%s", app_path, "wp-config.php");
            if (is_file(path)) {
                snprintf(path, sizeof(path), "%s/%s%s", app_path, wordpress, "wp-config.php");
            }
            else {
                wordpress[0] = '\0';
            }
            if (find_key_from_file(path, "WordPress", line, sizeof(line), 1) == 0) {
                if (strstr(line, "WordPress")) {
                    memset(app_name, 0x00, sizeof(app_name));
                    snprintf(app_name, sizeof(app_name), "%s", "WordPress");
                    memset(language, 0x00, sizeof(language));
                    snprintf(language, sizeof(language), "%s", "php");
                }
            }
            /* version: $wp_version = '5.6'; */
            memset(path, 0x00, sizeof(path));
            snprintf(path, sizeof(path), "%s/%s%s", app_path, wordpress, "wp-includes/version.php");
            if (find_key_from_file(path, "$wp_version", line, sizeof(line), 0) == 0) {
                tmp = strstr(line, "$wp_version");
                if (tmp) {
                    tmp += strlen("$wp_version");
                    i = 0;
                    while (*tmp != '\'') {
                        ++ tmp;
                        ++ i;
                        if (i >= sizeof(version)) break;
                    }
                    
                    if (i >= sizeof(version)) {
                        snprintf(version, sizeof(version), "%s", "None");
                    }
                    else {
                        ++ tmp;
                        *(tmp+i) = '\0';
                        snprintf(version, sizeof(version), "%s", tmp);
                    }
                }
            }
            else {
                snprintf(version, sizeof(version), "%s", "None");
            }
            cJSON *object = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "app_name", app_name);
            cJSON_AddStringToObject(object, "app_path", app_path);
            cJSON_AddStringToObject(object, "service_type", mid->type);
            cJSON_AddStringToObject(object, "version", version);
            cJSON_AddStringToObject(object, "language", language);
            cJSON_AddNumberToObject(object, "plugin_count", 0);
            cJSON_AddItemToArray(data->object, object);
            /* Web站点与Web应用部分数据来源相同 */
            snprintf(site_info[SITE_WORDPRESS].home_dir, sizeof(site_info[SITE_WORDPRESS].home_dir), "%s", app_path);
            snprintf(site_info[SITE_WORDPRESS].run_user, sizeof(site_info[SITE_WORDPRESS].run_user), "%s", mid->user);
            snprintf(site_info[SITE_WORDPRESS].pid, sizeof(site_info[SITE_WORDPRESS].pid), "%s", mid->pid);
            snprintf(site_info[SITE_WORDPRESS].service_type, sizeof(site_info[SITE_WORDPRESS].service_type), "%s", mid->type);
            supplement_apache_info(&site_info[SITE_WORDPRESS]);
            site_info[SITE_WORDPRESS].is_found = 1;
            break;
        }
        /* ThinkPHP */
        if (strncmp(iter_ent->d_name, "thinkphp", 13) == 0) {
            get_web_app_thinkphp(app_path, mid, data);
        }
    }

    closedir(dirp);

    return ret;

End:
    return -1;
}

/* 返回值，正常获取到返回 0，其它返回非 0
 * 从命令行中获取 java路径，拼上jeknins的war包 以获取版本信息
 * 以下为cmdline的内容
 * /etc/alternatives/java 
 * -Dcom.sun.akuma.Daemon=daemonized 
 * -Djava.awt.headless=true 
 * -DJENKINS_HOME=/var/lib/jenkins -jar 
 * /usr/lib/jenkins/jenkins.war 
 * --logfile=/var/log/jenkins/jenkins.log 
 * --webroot=/var/cache/jenkins/war 
 * --daemon --httpPort=8080 --ajp13Port=8009 --debug=5 
 * --handlerCountMax=100 --handlerCountMaxIdle=20
 * 执行命令
 * /etc/alternatives/java -jar /usr/lib/jenkins/jenkins.war --version
 */
static int get_old_jenkins_version(const char *pid, char *version, unsigned int ver_len)
{
    char path[PATH_MAX];
    char cmd[PATH_MAX];
    FILE *fp = NULL;
    char *tmp = NULL;
    int ret = 0;

    if (pid == NULL || version == NULL || ver_len == 0) {
        return -1;
    }

    memset (path, 0x00, sizeof(path));
    memset (cmd, 0x00, sizeof(cmd));

    tmp = get_cmd_line_by_pid(pid);
    if (!tmp) {
        return -1;
    }
    snprintf(path, sizeof(path), "%s", tmp);
    free(tmp);

    /* 获取java的路径 */
    tmp = strstr(path, "/java ");
    if (!tmp) {
        return -1;
    }
    tmp += 6;
    *tmp = '\0';

    ++ tmp;

    /* 获取jenkins的war目录 */
    tmp = strstr(tmp, "/usr/lib/jenkins/jenkins.war ");
    if (!tmp) {
        return -1;
    }
    *(tmp+29) = '\0';
    snprintf(cmd, sizeof(cmd), "%s -jar %s --version", path, tmp);

    if ((fp = popen(cmd, "r")) == NULL) {
        return -1;
    }

    memset (path, 0x00, sizeof(path));
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        if (strstr(path, "Running") || strstr(path, "webroot")) {
            continue;
        } else {
            snprintf(version, ver_len, "%s", path);
            tmp = strchr(version, '\n');
            if (tmp) {
                *tmp = '\0';
            }
            break;
        }
    }
    pclose(fp);

    if (!version[0]) {
        ret = 1;
    }

    return ret;
}
/**************************************************************************************************
 * 函数名: get_web_app_jenkins
 * 作用: 检测Jenkins应用，获取版本，路径等信息
 * 输入: data  连接每个模块Json信息，以及db描述符
 * 输出: Jenkins应用Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 查询daemon(Ubuntu)或者java(Centos)进程，
 *      版本，读取默认配置文件/var/lib/jenkins/config.xml，查找关键字<version>
 *      安装路径，进程路径
**************************************************************************************************/
static int get_web_app_jenkins(sys_info_t *data)
{
    char app_path[PATH_MAX];
    char line[PATH_MAX];
    char app_name[64];
    char version[64];
    char language[32];
    char app_pid[32];
    sqlite3_stmt * stmt = NULL;
    char *tmp = NULL;
    int ret = 0;
    const char *zTail;
    const char *query_process = "select pid,name,user from sys_process;";
    const char *conf_path = "/var/lib/jenkins/config.xml";

    if (data == NULL || data->object == NULL || data->db == NULL) {
        goto End;
    }

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, query_process, -1, &stmt, &zTail);
    if (ret !=SQLITE_OK){
        elog("No process info\n");
        goto End;
    }

    memset (app_path, 0x00, sizeof(app_path));

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *pid = sqlite3_column_text(stmt, 0);
        const char *process_path = sqlite3_column_text(stmt, 1);
        const char *process_user = sqlite3_column_text(stmt, 2);

        if (process_path[0] != '/') continue;

        memset (app_pid, 0x00, sizeof(app_pid));
        snprintf(app_pid, sizeof(app_pid), "%s", pid);
#ifdef SNIPER_FOR_DEBIAN
        if (strncmp(process_path, "/usr/bin/daemon", 15) == 0
                && strncmp(process_user, "jenkins", 7) == 0) {
            snprintf(app_path, sizeof(app_path), "%s", process_path);
            break;
        }
#else
        if (strncmp(process_path, "/usr/lib/jvm/java", 17) == 0 
                && strncmp(process_user, "jenkins", 7) == 0) {
            snprintf(app_path, sizeof(app_path), "%s", process_path);
            break;
        }
#endif
    }
    sqlite3_finalize(stmt);

    if (!app_path[0]) {
        goto End;
    }

    memset(app_name, 0x00, sizeof(app_name));
    snprintf(app_name, sizeof(app_name), "%s", "Jenkins");
    memset(language, 0x00, sizeof(language));
    snprintf(language, sizeof(language), "%s", "Java");
    /* version 
     * /var/lib/jenkins/config.xml  <version>2.289.2</version>
     */
    if (is_file(conf_path)==0 
            && find_key_from_file(conf_path, "<version>", line, sizeof(line), 1) == 0) {
        tmp = strstr(line, "<version>");
        if (tmp) {
            tmp += strlen("<version>");
            snprintf(version, sizeof(version), "%s", tmp);
            tmp = strchr(version, '<');
            if (tmp) {
                *tmp = '\0';
            } else {
                snprintf(version, sizeof(version), "%s", "");
                version[4] = '\0';
            }
        } else {
            snprintf(version, sizeof(version), "%s", "");
        }
    } else {
        /* 老版本去命令行里获取参数，执行以下命令
         * /etc/alternatives/java -jar /usr/lib/jenkins/jenkins.war --version
         */
        if (get_old_jenkins_version(app_pid, version, sizeof(version)) != 0) {
            version[0] = '\0';
        }
    }
    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "app_name", app_name);
    cJSON_AddStringToObject(object, "app_path", app_path);
    cJSON_AddStringToObject(object, "service_type", "none");
    cJSON_AddStringToObject(object, "version", version);
    cJSON_AddStringToObject(object, "language", language);
    cJSON_AddNumberToObject(object, "plugin_count", 0);
    cJSON_AddItemToArray(data->object, object);
    site_info[SITE_JENKINS].is_found = 1;

    return ret;
End:
    return -1;
}
/* JSON web_app */
void *sys_web_app_info(sys_info_t *data)
{
    int i = 0;

    if (data->object == NULL) return NULL;

    for (i = 0; i < MID_MAX; i++) {
        switch (midd_set[i].midd_type) {
        case MID_APACHE:
            get_apache_web_app(&midd_set[i], data);
            break;
        case MID_NGINX:
            break;
        case MID_TOMCAT:
            break;
        case MID_JBOSS:
            break;
        case MID_WEBLOGIC:
            break;
        case MID_JETTY:
            break;
        case MID_WEBSPHERE:
            break;
        case MID_WILDFLY:
            break;
        default:
            break;
        }
    }
    /* jenkins不依赖apache、nginx、tomcat这样的中间件 */
    get_web_app_jenkins(data);

    return NULL;
}
void *sys_web_app_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}

/* 发现框架名和版本返回 0，其它返回非0 */
static int find_web_frame_info_from_json(const char *file, char *frame_name, char *version, int version_len)
{
    char source_line[PATH_MAX];
    char line[PATH_MAX];
    char lower_name[64] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    int len = 0;
    int i = 0;
    int found_name = 0;
    int found_version = 0;

    if (file == NULL || frame_name == NULL || version == NULL || version_len <= 0) {
        return -1;
    }

    if (is_file(file) != 0) {
        return -1;
    }

    len = strlen(frame_name);
    for (i=0; i<=len; i++) {
        lower_name[i] = tolower(frame_name[i]);
    }

    fp = fopen(file, "r");
    if (!fp) {
        return -1;
    }

    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '<' || line[0] == '\n') {
            continue;
        }

        // 保留一份原字符串
        memset(source_line, 0x00, sizeof(source_line));
        snprintf(source_line, sizeof(source_line), "%s", line);

        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }
        tmp = strstr(line, lower_name);
        if (tmp) {
            found_name = 1;
        }

        if (found_version) { /* 只保留第一个发现的version信息 */
            if (found_name) {
                break;
            }
            continue;
        }
        tmp = strstr(line, "version");
        if (tmp) {
            /* 发现版本信息去原始字符串中找 */
            tmp = strchr(source_line, ':');
            if (!tmp) {
                continue;
            }
            ++ tmp;

            tmp = strchr(tmp, '\"');
            if (!tmp) {
                continue;
            }
            ++ tmp;
            memset (version, 0x00, sizeof(version_len));
            snprintf(version, version_len, "%s", tmp);
            tmp = strchr(version, '\"');
            if (tmp) {
                *tmp = '\0';
            }
            found_version = 1;
        }
    }
    fclose(fp);

    return !(found_name & found_version);
}

static int find_web_frame_corethink_info_from_sql(const char *file, char *frame_name, char *version, int version_len)
{
    char source_line[PATH_MAX];
    char line[PATH_MAX];
    FILE *fp = NULL;
    char *tmp = NULL;

    if (file == NULL || frame_name == NULL || version == NULL || version_len <= 0) {
        return -1;
    }

    memset (version, 0x00, sizeof(version_len));

    if (is_file(file) != 0) {
        return -1;
    }

    fp = fopen(file, "r");
    if (!fp) {
        return -1;
    }

    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        tmp = strstr(line, "CoreThink");
        if (!tmp) {
            continue;
        }
        tmp += 9;
        tmp = strchr(tmp, ',');
        if (!tmp) {
            continue;
        }
        ++ tmp;

        tmp = strchr(tmp, '\'');
        if (!tmp) {
            continue;
        }
        ++ tmp;

        snprintf(version, version_len, "%s", tmp);
        tmp = strchr(version, '\'');
        if (tmp) {
            *tmp = '\0';
        }
        break;
    }
    fclose(fp);

    return 0;
}

/**************************************************************************************************
 * 函数名: match_file_with_regex
 * 作用: 使用正则，检测文件中关键字，并返回查到的字符串
 * 输入: file       指定的文件路径
 *      regex      正则表达式字符串
 *      result     存放结果的buf
 *      result_len 存放结果的buf长度
 * 输出: 输出正则匹配到的字符串到result中
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 无
**************************************************************************************************/
static int match_file_with_regex(const char *file, const char *regex, char *result, const int result_len)
{
    char line[PATH_MAX];
    int ovector[256];
    int ret = 0;
    int i = 0;
    int erroffset = 0;
    int rc = 0;
    int rc2 = 0;
    int len = 0;
    const char *error;
    pcre *re;
    FILE *fp = NULL;

    if (file == NULL || regex == NULL || result == NULL || result_len <= 1) {
        return -1;
    }

    if (is_file(file) != 0) {
        return -1;
    }

    fp = fopen(file, "r");
    if (!fp) {
        return -1;
    }

    re = pcre_compile(regex, 0, &error, &erroffset, NULL);
    if (re == NULL) {
        fclose(fp);
        return -1;
    }

    memset(line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        rc = pcre_exec(re, NULL, line, strlen(line), 0, 0, ovector, sizeof(ovector));
        if(rc == PCRE_ERROR_NOMATCH) {
            ret = 0;
        }
        else if(rc < -1) {
            ret = -1;
        }
        else {
            for(i=0; i<rc; i++) {
                const char *substring;
                rc2 = pcre_get_substring(line, ovector, rc, i, &substring);
                // dlog("%d: version:%s\n",i,substring);
                if (i == 0) {
                    snprintf(result, result_len, "%s", substring);
                    ret = 1;
                }
                pcre_free_substring(substring);
            }
        }

        if (ret == 1) {
            break;
        }
    }

    pcre_free(re);
    fclose(fp);

    return ret;
 }

/* 在指定目录下查找特定文件名[扩展名]
 * 找到返回 1，其它返回非 1
 */
 static int find_file_in_dir(const char *path, const char *filename, const char *extension,
                            char *target_file, int target_len)
 {
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    char *tmp = NULL;
    int ret = 0;

    if (path == NULL || filename == NULL) {
        return -1;
    }

    if (is_dir(path) != 0) {
        return -1;
    }

    dirp = opendir(path);
    if (dirp == NULL) {
        return -1;;
    }
    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] == '.') {
            continue;
        }

        tmp = strstr(dent->d_name, filename);
        if (tmp) {
            ret = 1;
        }

        if (ret == 1 && extension) {
            if (!strstr(tmp, extension)) { /* 扩展名不符合 */
                ret = 0;
            }
        }

        if (ret) {
            if (target_file && target_len > 1) {
                memset (target_file, 0x00, target_len);
                snprintf(target_file, target_len, "%s", tmp);
            }
            break;
        }
    }
    closedir(dirp);

    return ret;
 }

 
 static int get_java_spring_info(sys_info_t *data, const midd_t *tomcat)
 {
    char line[PATH_MAX];
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    char version[64];
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    char *tmp = NULL;
    int ret = 0;
    const char *spring_version = "spring-core-";

    if (data == NULL || data->object == NULL || tomcat == NULL) {
        return -1;
    }

    if (web_framework[WEBFRAME_SPRING] == 1) {
        return 0;
    }

    if (is_dir(tomcat->access_path) != 0) {
        return -1;
    }
    memset (version, 0x00, sizeof(version));
    memset (tmp_path, 0x00, sizeof(tmp_path));
    snprintf(tmp_path, sizeof(tmp_path), "%s", tomcat->access_path);
    tmp = strstr(tmp_path, "/ROOT");
    if (tmp) {
        *tmp = '\0';
    }

    dirp = opendir(tmp_path);
    if (dirp == NULL) {
        return -1;
    }
    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] == '.') {
            continue;
        }
         /* 查找与ROOT平级的，目录下的有spring-core-x.x.x.jar文件也视为srping框架 */
        memset (path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/%s/WEB-INF/lib/", tmp_path, dent->d_name);

        if (find_file_in_dir(path, spring_version, ".jar", line, sizeof(line)) == 1) {
            tmp = strstr(line, spring_version);
            if (tmp) {
                tmp += strlen(spring_version);
                snprintf(version, sizeof(version), "%s", tmp);
                tmp = strstr(version, ".jar");
                if (tmp) {
                    *tmp = '\0';
                } else {
                    memset (version, 0x00, sizeof(version));
                }
            }
            break;
        }
    }
    closedir(dirp);

    /* 因spring框架检测是查找指定文件，并以文件名中的版本作为框架版本
     * 若未找到版本信息，则视为框架未检测到，不上报
     */
    if (!version[0]) {
        return -1;
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    cJSON_AddStringToObject(object, "framework_version", version);
    cJSON_AddStringToObject(object, "framework_path", path);
    cJSON_AddStringToObject(object, "framework_name", "Spring");
    cJSON_AddStringToObject(object, "framework_language", "Java");

    web_framework[WEBFRAME_SPRING] = 1;

    return ret;
 }

/* spring mvc是一种代码模块逻辑结构，依附于spring的框架
 * spring-webmvc-文件来确定是否有spring mvc的存在
 */
 static int get_java_springmvc_info(sys_info_t *data, const midd_t *tomcat)
 {
    char line[PATH_MAX];
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    char version[64];
    const char *key = "VERSION";
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    char *tmp = NULL;
    int ret = 0;
    int found = 0;
    const char *sprintmvc_versoin = "spring-webmvc-";

    if (data == NULL || data->object == NULL || tomcat == NULL) {
        return -1;
    }

    if (web_framework[WEBFRAME_SPRINGMVC] == 1) {
        return 0;
    }

    if (is_dir(tomcat->access_path) != 0) {
        return -1;
    }
    memset (version, 0x00, sizeof(version));
    memset (tmp_path, 0x00, sizeof(tmp_path));
    snprintf(tmp_path, sizeof(tmp_path), "%s", tomcat->access_path);
    tmp = strstr(tmp_path, "/ROOT");
    if (tmp) {
        *tmp = '\0';
    }

    dirp = opendir(tmp_path);
    if (dirp == NULL) {
        return -1;
    }
    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] == '.') {
            continue;
        }
         /* 查找与ROOT平级的，目录下的有spring-core-x.x.x.jar文件也视为struts框架 */
        memset (path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/%s/WEB-INF/lib/", tmp_path, dent->d_name);

        if (find_file_in_dir(path, sprintmvc_versoin, ".jar", line, sizeof(line)) == 1) {
            tmp = strstr(line, sprintmvc_versoin);
            if (tmp) {
                tmp += strlen(sprintmvc_versoin);
                snprintf(version, sizeof(version), "%s", tmp);
                tmp = strstr(version, ".jar");
                if (tmp) {
                    *tmp = '\0';
                } else {
                    memset (version, 0x00, sizeof(version));
                }
            }
            break;
        }
    }
    closedir(dirp);

    /* 因struts框架检测是查找指定文件，并以文件名中的版本作为框架版本
     * 若未找到版本信息，则视为框架未检测到，不上报
     */
    if (!version[0]) {
        return -1;
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    cJSON_AddStringToObject(object, "framework_version", version);
    cJSON_AddStringToObject(object, "framework_path", path);
    cJSON_AddStringToObject(object, "framework_name", "Spring MVC");
    cJSON_AddStringToObject(object, "framework_language", "Java");

    web_framework[WEBFRAME_SPRINGMVC] = 1;

    return ret;
 }

/**************************************************************************************************
 * 函数名: get_java_struts_info
 * 作用: 检测PHP web框架struts，获取版本，路径信息
 * 输入: data  连接每个模块Json信息，以及db描述符
 * 输出: struts框架Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 
**************************************************************************************************/
static int get_java_struts_struts2_info(sys_info_t *data, const midd_t *tomcat, const int struts_type)
{
    char line[PATH_MAX];
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    char version[64];
    const char *key = "VERSION";
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    char *tmp = NULL;
    int ret = 0;
    int found = 0;
    const char *struts_version;

    if (data == NULL || data->object == NULL || tomcat == NULL) {
        return -1;
    }

    if (struts_type == 1) {
        if (web_framework[WEBFRAME_STRUTS] != 0) {
            return 0;
        }
        struts_version = "struts-core-";
    } else if (struts_type == 2) {
        if (web_framework[WEBFRAME_STRUTS2] != 0) {
            return 0;
        }
        struts_version = "struts2-core-";
    } else {
        return -1;
    }

    if (is_dir(tomcat->access_path) != 0) {
        return -1;
    }
    memset (version, 0x00, sizeof(version));
    memset (tmp_path, 0x00, sizeof(tmp_path));
    snprintf(tmp_path, sizeof(tmp_path), "%s", tomcat->access_path);
    tmp = strstr(tmp_path, "/ROOT");
    if (tmp) {
        *tmp = '\0';
    }

    dirp = opendir(tmp_path);
    if (dirp == NULL) {
        return -1;
    }
    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] == '.') {
            continue;
        }
         /* 查找与ROOT平级的，目录下的有struts-core-x.x.x.jar文件也视为struts框架 */
        memset (path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/%s/WEB-INF/lib/", tmp_path, dent->d_name);

        if (find_file_in_dir(path, struts_version, ".jar", line, sizeof(line)) == 1) {
            tmp = strstr(line, struts_version);
            if (tmp) {
                tmp += strlen(struts_version);
                snprintf(version, sizeof(version), "%s", tmp);
                tmp = strstr(version, ".jar");
                if (tmp) {
                    *tmp = '\0';
                } else {
                    memset (version, 0x00, sizeof(version));
                }
            }
            break;
        }
    }
    closedir(dirp);

    /* 因struts框架检测是查找指定文件，并以文件名中的版本作为框架版本
     * 若未找到版本信息，则视为框架未检测到，不上报
     */
    if (!version[0]) {
        return -1;
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    cJSON_AddStringToObject(object, "framework_version", version);
    cJSON_AddStringToObject(object, "framework_path", path);
    if (struts_type == 1) {
        cJSON_AddStringToObject(object, "framework_name", "struts");
    } else {
        cJSON_AddStringToObject(object, "framework_name", "struts2");
    }
    cJSON_AddStringToObject(object, "framework_language", "Java");

    if (struts_type == 1) {
        web_framework[WEBFRAME_STRUTS] = 1;
    } else if (struts_type == 2) {
        web_framework[WEBFRAME_STRUTS2] = 1;
    }

    return ret;
}
/* 检查有没有检测到web框架
 * 返回值，0未检测到，1检测到
 */
static int is_found_web_framework()
{
    int i = 0;
    int ret = 0;
    for (i=0; i<sizeof(web_framework); i++) {
        if (web_framework[i] == 1) {
            ret = 1;
            break;
        }
    }

    return ret;
}
/**************************************************************************************************
 * 函数名: get_web_framework_info
 * 作用: 顺序检测相关web框架
 * 输入: data 
 * 输出: 所有检测到的web框架Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 无
**************************************************************************************************/
static int get_web_framework_info(sys_info_t *data, const midd_t *middleware)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    int ret = 0;
    int i = 0;
    int found = 0;

    if (data->object == NULL || data->db == NULL || middleware == NULL) {
        return -1;
    }

    i = 0;
    while (web_frame_info[i].cheak_file[0]) {
        if (web_framework[web_frame_info[i].type] == 1) { // 已经查到了不重复查
            i ++;
            continue;
        }

        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/%s", middleware->access_path, web_frame_info[i].cheak_file);

        if (is_file(path) != 0) {
            i ++;
            continue;
        }

        if (web_frame_info[i].flag && found != web_frame_info[i].type) {
            found = web_frame_info[i].type;
        }

        if (web_frame_info[i].flag == WEBFRAME_PHPIXIE) { /* 因为新版本原因框架名和版本需要特殊处理的 */
            if (find_web_frame_info_from_json(path, web_frame_info[i].name, line, sizeof(line)) == 0) {
                ret = 1;
                goto INSERT;
            }
        }

        if (web_frame_info[i].flag == WEBFRAME_CORETHINK) { /* corePHP框架特定版本特殊处理，从sql文件中获取版本信息 */
            if (find_web_frame_corethink_info_from_sql(path, web_frame_info[i].name, line, sizeof(line)) == 0) {
                if (line[0]) {
                    ret = 1;
                    goto INSERT;
                }
            }
        }

        if (web_frame_info[i].flag == WEBFRAME_FLIGHT) {
            if (return_file_first_line(path, line, sizeof(line)) == 0) {
                if (line[0]) {
                    ret = 1;
                    goto INSERT;
                }
            }
        }

        if (web_frame_info[i].flag) { // flag是1表示该文件只要存在即可，0表需要下面正则去匹配
            i ++;
            continue;
        }

        if (found != web_frame_info[i].type) {
            i ++;
            continue;
        }
        // dlog("-(%d)--%d--%d---%s--%s\n", i, found, web_frame_info[i].type, path, web_frame_info[i].regex);
        memset (line, 0x00, sizeof(line));
        ret = match_file_with_regex(path, web_frame_info[i].regex, line, sizeof(line));
INSERT:
        if (ret == 1 && line[0]) {
            cJSON *object = cJSON_CreateObject();
            cJSON_AddItemToArray(data->object, object);
            cJSON_AddStringToObject(object, "framework_version", line);
            cJSON_AddStringToObject(object, "framework_path", middleware->access_path);
            cJSON_AddStringToObject(object, "framework_name", web_frame_info[i].name);
            cJSON_AddStringToObject(object, "framework_language", web_frame_info[i].language);
            // dlog("===%d====%s===%s\n", ret, web_frame_info[i].name, line);
            web_framework[web_frame_info[i].type] = 1;
            break;
        }

        i ++;
    }

    return 0;
}

/* 针对中间件root目录中部署多个站点的情况，再增加一层目录，检测web框架 */
static int get_dir_web_framework(sys_info_t *data, midd_t *middleware)
{
    char path[PATH_MAX];
    int ret = 0;
    int len = 0;
    DIR *dirp = NULL;
    struct dirent *dir = NULL;

    if (data == NULL || data->object == NULL || middleware == NULL) {
        return -1;
    }

    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", middleware->access_path);

    dirp = opendir(path);
    if (!dirp) {
        return -1;
    }

    while ((dir = readdir(dirp)) != NULL) {
        if (dir->d_type != DT_DIR) {
            continue;
        }

        if (dir->d_name[0] == '.') {
            continue;
        }

        len = strlen(middleware->access_path);
        if (middleware->access_path[len-1] == '/') {
            middleware->access_path[len-1] = '\0';
            -- len;
        }
        snprintf(middleware->access_path + len, PATH_MAX-len, "/%s", dir->d_name);
        get_web_framework_info(data, middleware);
        *(middleware->access_path + len) = '\0';
    }
    closedir(dirp);

    return ret;
}
static int is_filename_in_dir(const char *path, const char *filename, char *result, const int result_len)
{
    DIR *dirp = NULL;
    struct dirent *dir = NULL;
    char *tmp = NULL;

    if (path == NULL || filename == NULL || result == NULL || result_len == 0) {
        return -1;
    }

    dirp = opendir(path);
    if (dirp) {
        while ((dir = readdir(dirp)) != NULL) {
            if (dir->d_name[0] == '.') {
                continue;
            }
            tmp = strstr(dir->d_name, filename);
            if (tmp) {
                memset(result, 0x00, result_len);
                snprintf(result, result_len, "%s", dir->d_name);
            }
        }
        closedir(dirp);
    } else {
        return -1;
    }

    return 0;
}
/**************************************************************************************************
 * 函数名: get_python_flask_info
 * 作用: 检测Python web框架flask，获取版本，路径信息
 * 输入: pid   进程pid
 *      data  连接每个模块Json信息，以及db描述符
 * 输出: flask框架 Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 通过/proc/pid/exe获取python的绝对路径，获取site-packages所在路径
 *      版本，查找以Flask-开头的目录，并读取文件METADATA文件中Version:关键字
 *      安装路径，/proc/pid/exe获取python的绝对路径
**************************************************************************************************/
static int get_python_flask_info(const char *pid, sys_info_t *data)
{
    char abs_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char version[64] = {0};
    char *tmp = NULL;
    char *end = NULL;
    int len = 0;
    int ret = 0;
    int fd = 0;

    if (pid == NULL || data == NULL || data->object == NULL) return -1;

    if (web_framework[WEBFRAME_Flask] != 0) {
        return 0;
    }

    memset(path, 0x00, sizeof(path));
    memset(abs_path, 0x00, sizeof(abs_path));
    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    len = readlink(path, abs_path, PATH_MAX);

    if (len < 0) {
        return -1;
    }

    /* /usr/local/python3/lib/python3.6/site-packages
     * /usr/local/python3/bin/python3.6
     */
    tmp = strstr(abs_path, "/bin/python");
    if (tmp) {
        *tmp = '\0';

        memset(path, 0x00, sizeof(path));
        memset(line, 0x00, sizeof(line));
        snprintf(path, sizeof(path), "%s/lib", abs_path);

        len = strlen(path);
        if (is_filename_in_dir(path, "python", line, sizeof(line)) != 0) { /* 确定带版本的Python目录 */
            return -1;
        }

        snprintf(path+len, sizeof(path)-len, "/%s/site-packages", line);
        if (is_dir(path) != 0) {
            return -1;
        }
        /* 框架所在的目录 */
        memset(abs_path, 0x00, sizeof(abs_path));
        snprintf(abs_path, sizeof(abs_path), "%s", path);
        len = strlen(path);
        memset(line, 0x00, sizeof(line));
        /* 获取Flask的版本所在目录 */
        if (is_filename_in_dir(path, "Flask-", line, sizeof(line)) != 0) {
            return -1;
        }

        snprintf(path+len, sizeof(path)-len, "/%s/METADATA", line);
        memset(line, 0x00, sizeof(line));
        memset(version, 0x00, sizeof(version));

        if (is_file(path) == 0
            && find_key_from_file(path, "Version:", line, sizeof(line), 0) == 0) {
            tmp = strstr(line, "Version:");
            if (tmp) {
                tmp += strlen("Version:");
                while(*tmp == ' ') {
                    tmp ++;
                }
                snprintf(version, sizeof(version), "%s", tmp);
                len = strlen(version);
                if (version[len-1] == '\n') {
                    version[len-1] = '\0';
                }
            }
        }
    } 
    if (!version[0]) {
        /* 虚拟环境引用的情况与安装在系统中的情况类似
         * 去/proc/pid/environ中找FLASK_APP=关键字确认是flask的应用
         * 再通过VIRTUAL_ENV=确定目录，再在VIRTUAL_ENV的目录里找lib/lib64下的site-packages
         * site-packages目录中一般一个包会有两个目录对应，比如flask和flask-0.62-py3.6.egg-info
         * 其中一个会带有相应的版本信息，此版本信息会随着pipe/pip3命令解析的依赖包的不而不同
         * 即，同一个python3的环境，用pip/pip3安装的版本可能会不同，属于正常的
         */
        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "/proc/%s/environ", pid);
        memset(line, 0x00, sizeof(line));
        fd = open(path, O_RDONLY);
        len = read(fd, line, sizeof(line));
        end = line + len;
        for (tmp=line; tmp<end; tmp++) {
            if (*tmp == 0) {
                *tmp = ' ';
            }
        }
        close(fd);

        tmp = strstr(line, "FLASK_APP=");
        if (!tmp) {
            return -1;
        }
        tmp = strstr(line, "VIRTUAL_ENV=");
        if (!tmp) {
            return -1;
        }
        tmp += 12;
        snprintf(abs_path, sizeof(abs_path), "%s", tmp);
        tmp = strchr(abs_path, ' ');
        if (tmp) {
            *tmp = '\0';
        }

        int flags = 0;
try_again:
        memset(version, 0x00, sizeof(version));
        memset(path, 0x00, sizeof(path));
        if (!flags) { /* 32位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", abs_path, "/lib/");
        } else { /* 64位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", abs_path, "/lib64/");
        }
        memset (line, 0x00, sizeof(line));
        if (find_file_in_dir(path, "Flask-", NULL, line, sizeof(line)) == 1) {
            tmp = strstr(line, "Flask-");
            if (!tmp) {
                return -1;
            }
            tmp += 7;
            snprintf(version, sizeof(version), "%s", tmp);
            tmp = strchr(version, '-');
            if (tmp) {
                *tmp = '\0';
            }
        }
        if (!version[0] && flags == 0) {
            flags = 1;
            goto try_again;
        }
    }

    if (!version[0]) {
        snprintf(version, sizeof(version), "%s", "None");
    } 

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    cJSON_AddStringToObject(object, "framework_version", version);
    cJSON_AddStringToObject(object, "framework_path", abs_path);
    cJSON_AddStringToObject(object, "framework_name", "Flask");
    cJSON_AddStringToObject(object, "framework_language", "Python");

    web_framework[WEBFRAME_Flask] = 1;

    return ret;
}
/**************************************************************************************************
 * 函数名: get_python_tornado_info
 * 作用: 检测Python web框架tornado，获取版本，路径信息
 * 输入: pid   进程pid
 *      data  连接每个模块Json信息，以及db描述符
 * 输出: tornado框架 Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 通过/proc/pid/exe获取python的绝对路径，获取site-packages所在路径
 *      版本，查找以tornado-开头的目录，并读取文件METADATA文件中Version:关键字
 *      安装路径，/proc/pid/exe获取python的绝对路径
**************************************************************************************************/
static int get_python_tornado_info(const char *pid, sys_info_t *data)
{
    char abs_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char version[64] = {0};
    char *tmp = NULL;
    int len = 0;
    int ret = 0;

    if (pid == NULL || data == NULL || data->object == NULL) return -1;

    if (web_framework[WEBFRAME_Tornado] != 0) {
        return -1;
    }

    memset(path, 0x00, sizeof(path));
    memset(abs_path, 0x00, sizeof(abs_path));
    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    len = readlink(path, abs_path, PATH_MAX);
    if (len < 0) {
        return -1;
    }

    tmp = strstr(abs_path, "/bin/python");
    if (tmp) { /* 框架源码直接使用的情况，例 python(2/3) web2py.py */
        *tmp = '\0';

        memset(path, 0x00, sizeof(path));
        memset(line, 0x00, sizeof(line));
        snprintf(path, sizeof(path), "%s/lib", abs_path);

        len = strlen(path);
        if (is_filename_in_dir(path, "python", line, sizeof(line)) != 0) { /* 确定带版本的Python目录 */
            return -1;
        }

        snprintf(path+len, sizeof(path)-len, "/%s/site-packages", line);
        if (is_dir(path) != 0) {
            return -1;
        }
        /* 框架所在的目录 */
        memset(abs_path, 0x00, sizeof(abs_path));
        snprintf(abs_path, sizeof(abs_path), "%s", path);
        len = strlen(path);
        memset(line, 0x00, sizeof(line));
        /* 获取Flask的版本所在目录 */
        if (is_filename_in_dir(path, "tornado-", line, sizeof(line)) != 0) {
            return -1;
        }

        snprintf(path+len, sizeof(path)-len, "/%s/METADATA", line);
        memset(line, 0x00, sizeof(line));
        memset(version, 0x00, sizeof(version));

        if (is_file(path) == 0
            && find_key_from_file(path, "Version:", line, sizeof(line), 0) == 0) {
            tmp = strstr(line, "Version:");
            if (tmp) {
                tmp += strlen("Version:");
                while(*tmp == ' ') {
                    tmp ++;
                }
                snprintf(version, sizeof(version), "%s", tmp);
                len = strlen(version);
                if (version[len-1] == '\n') {
                    version[len-1] = '\0';
                }
            }
        }
    }

    if (!version[0]) { /* 上面没查到再查一遍库安装的情况 */
        /* 对于直接运行的情况，python3 ./abc.py 只需在abc.py 使用import web引用该框架包即可
         * 去当前python版本的安装目录找site-packages目录，再查对应的框架包名
         * 默认安装目录，Centos/Ubuntu是一致的/usr/local/lib/python(2.7/3.x)/site-packages/
         * TODO 非默认安装需要再区分是不是虚拟环境中的python环境，这种可以没有任何依赖直接运行一个应用(框架)
         * site-packages目录中一般一个包会有两个目录对应，比如tornado和tornado-6.1.dist-info
         * 其中一个会带有相应的版本信息，此版本信息会随着pipe/pip3命令解析的依赖包的不而不同
         * 即，同一个python3的环境，用pip/pip3安装的版本可能会不同，属于正常的
         */
        memset(path, 0x00, sizeof(path));
        memset(abs_path, 0x00, sizeof(abs_path));
        snprintf(path, sizeof(path), "/proc/%s/exe", pid);
        len = readlink(path, abs_path, PATH_MAX);
        if (len < 0) {
            return -1;
        }
        /* 只看/usr/bin/python部分，不关心具体哪个版本
         * 能匹配上按默认安装的python的环境找site-packages
         */
        if (strncmp(abs_path, "/usr/bin/python", 15) != 0) {
            return -1;
        }

        int flags = 0;
try_again:
        memset(version, 0x00, sizeof(version));
        memset(path, 0x00, sizeof(path));
        if (!flags) { /* 32位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", "/usr/local/lib/", basename(abs_path));
        } else { /* 64位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", "/usr/local/lib64/", basename(abs_path));
        }
        memset (line, 0x00, sizeof(line));
        if (find_file_in_dir(path, "tornado-", NULL, line, sizeof(line)) == 1) {
            tmp = strstr(line, "tornado-");
            if (!tmp) {
                return -1;
            }
            tmp += 8;
            snprintf(version, sizeof(version), "%s", tmp);
            tmp = strstr(version, ".dist");
            if (tmp) {
                *tmp = '\0';
            }
        }
        if (!version[0] && flags == 0) {
            flags = 1;
            goto try_again;
        }
    }

    if (!version[0]) {
        return -1;
    } 

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    cJSON_AddStringToObject(object, "framework_version", version);
    cJSON_AddStringToObject(object, "framework_path", abs_path);
    cJSON_AddStringToObject(object, "framework_name", "Tornado");
    cJSON_AddStringToObject(object, "framework_language", "Python");

    web_framework[WEBFRAME_Tornado] = 1;

    return ret;
}

/**************************************************************************************************
 * 函数名: get_python_webpy_info
 * 作用: 检测Python web框架webpy，获取版本，路径信息
 * 输入: pid   进程pid
 *      data  连接每个模块Json信息，以及db描述符
 * 输出: webpy框架 Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 通过/proc/pid/exe获取python的绝对路径，获取site-packages所在路径
 *      版本，查找以web.py-开头的目录，并读取文件PKG-INFO文件中Version:关键字
 *      安装路径，/proc/pid/exe获取python的绝对路径
**************************************************************************************************/
static int get_python_webpy_info(const char *pid, sys_info_t *data)
{
    char abs_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char version[64] = {0};
    char *tmp = NULL;
    int len = 0;
    int ret = 0;

    if (pid == NULL || data == NULL || data->object == NULL) return -1;

    if (web_framework[WEBFRAME_Webpy] != 0) {
        return -1;
    }

    memset(path, 0x00, sizeof(path));
    memset(abs_path, 0x00, sizeof(abs_path));
    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    len = readlink(path, abs_path, PATH_MAX);
    if (len < 0) {
        return -1;
    }

    tmp = strstr(abs_path, "/bin/python");
    if (tmp) { /* 框架源码直接使用的情况，例 python(2/3) web2py.py */
        *tmp = '\0';
        memset(path, 0x00, sizeof(path));
        memset(line, 0x00, sizeof(line));
        snprintf(path, sizeof(path), "%s/lib", abs_path);

        len = strlen(path);
        if (is_filename_in_dir(path, "python", line, sizeof(line)) != 0) { /* 确定带版本的Python目录 */
            return -1;
        }

        snprintf(path+len, sizeof(path)-len, "/%s/site-packages", line);
        if (is_dir(path) != 0) {
            return -1;
        }
        /* 框架所在的目录 */
        memset(abs_path, 0x00, sizeof(abs_path));
        snprintf(abs_path, sizeof(abs_path), "%s", path);
        len = strlen(path);
        memset(line, 0x00, sizeof(line));
        /* 获取web.py的版本所在目录 */
        if (is_filename_in_dir(path, "web.py-", line, sizeof(line)) != 0) {
            return -1;
        }

        snprintf(path+len, sizeof(path)-len, "/%s/PKG-INFO", line);
        memset(line, 0x00, sizeof(line));
        memset(version, 0x00, sizeof(version));

        if (is_file(path) == 0
            && find_key_from_file(path, "Version:", line, sizeof(line), 0) == 0) {
            tmp = strstr(line, "Version:");
            if (tmp) {
                tmp += strlen("Version:");
                while(*tmp == ' ') {
                    tmp ++;
                }
                snprintf(version, sizeof(version), "%s", tmp);
                len = strlen(version);
                if (version[len-1] == '\n') {
                    version[len-1] = '\0';
                }
            }
        }
    }

    if (!version[0]) { /* 上面没查到再查一遍库安装的情况 */
        /* 对于直接运行的情况，python3 ./abc.py 只需在abc.py 使用import web引用该框架包即可
         * 去当前python版本的安装目录找site-packages目录，再查对应的框架包名
         * 默认安装目录，Centos/Ubuntu是一致的/usr/local/lib/python(2.7/3.x)/site-packages/
         * TODO 非默认安装需要再区分是不是虚拟环境中的python环境，这种可以没有任何依赖直接运行一个应用(框架)
         * site-packages目录中一般一个包会有两个目录对应，比如web和web.py-0.62-py3.6.egg-info
         * 其中一个会带有相应的版本信息，此版本信息会随着pipe/pip3命令解析的依赖包的不而不同
         * 即，同一个python3的环境，用pip/pip3安装的版本可能会不同，属于正常的
         */
        memset(path, 0x00, sizeof(path));
        memset(abs_path, 0x00, sizeof(abs_path));
        snprintf(path, sizeof(path), "/proc/%s/exe", pid);
        len = readlink(path, abs_path, PATH_MAX);
        if (len < 0) {
            return -1;
        }
        /* 只看/usr/bin/python部分，不关心具体哪个版本
         * 能匹配上按默认安装的python的环境找site-packages
         */
        if (strncmp(abs_path, "/usr/bin/python", 15) != 0) {
            return -1;
        }
        int flags = 0;
try_again:
        memset(version, 0x00, sizeof(version));
        memset(path, 0x00, sizeof(path));
        if (!flags) { /* 32位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", "/usr/local/lib/", basename(abs_path));
        } else { /* 64位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", "/usr/local/lib64/", basename(abs_path));
        }
        memset (line, 0x00, sizeof(line));
        if (find_file_in_dir(path, "web.py-", NULL, line, sizeof(line)) == 1) {
            tmp = strstr(line, "web.py-");
            if (!tmp) {
                return -1;
            }
            tmp += 7;
            snprintf(version, sizeof(version), "%s", tmp);
            tmp = strchr(version, '-');
            if (tmp) {
                *tmp = '\0';
            }
        }
        if (!version[0] && flags == 0) {
            flags = 1;
            goto try_again;
        }
    }

    if (!version[0]) {
        return -1;
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    cJSON_AddStringToObject(object, "framework_version", version);
    cJSON_AddStringToObject(object, "framework_path", abs_path);
    cJSON_AddStringToObject(object, "framework_name", "Web.py");
    cJSON_AddStringToObject(object, "framework_language", "Python");

    web_framework[WEBFRAME_Webpy] = 1;

    return ret;
}

static int get_php_yii_info(const char *pid, sys_info_t *data)
{
    char abs_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    unsigned char line[PATH_MAX] = {0};
    char version[64] = {0};
    int len = 0;
    int ret = 0;
    int fd = 0;
    int found = 0;
    int i = 0;
    unsigned char *tmp = NULL;
    unsigned char *end = NULL;

    if (pid == NULL || data == NULL || data->object == NULL) {
        return -1;
    }

    if (web_framework[WEBFRAME_YII] != 0) {
        return -1;
    }

    /* get cmdline */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    tmp = strstr(line, "yii");
    if (!tmp) {
        return -1;
    }

    /* 读取/proc/pid/environ，查找PWD=关键字，确定目录 */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/environ", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    tmp = strstr(line, "PWD=");
    if (!tmp) {
        return -1;
    }
    tmp += 4;

    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", tmp);
    tmp = strchr(path, ' ');
    if (tmp) {
        *tmp = '\0';
    }

    if (is_dir(path) != 0) {
        return -1;
    }

    len = strlen(path);

    while (web_frame_info[i].cheak_file[0]) {
        if (web_frame_info[i].type != WEBFRAME_YII) {
            ++ i;
            continue;
        }

        if (web_framework[web_frame_info[i].type] == 1) { // 已经查到了不重复查
            i ++;
            continue;
        }
        path[len] = '\0';
        snprintf(path+len, sizeof(path)-len, "%s", web_frame_info[i].cheak_file);

        if (is_file(path) != 0) {
            i ++;
            continue;
        }

        if (web_frame_info[i].flag && found != web_frame_info[i].type) {
            found = web_frame_info[i].type;
        }

        if (web_frame_info[i].flag == WEBFRAME_YII) { /* 因为新版本原因框架名和版本需要特殊处理的 */
        }

        if (web_frame_info[i].flag) { // flag是1表示该文件只要存在即可，0表需要下面正则去匹配
            i ++;
            continue;
        }

        if (found != web_frame_info[i].type) {
            i ++;
            continue;
        }
        // dlog("-(%d)--%d--%d---%s--%s\n", i, found, web_frame_info[i].type, path, web_frame_info[i].regex);
        memset (line, 0x00, sizeof(line));
        ret = match_file_with_regex(path, web_frame_info[i].regex, line, sizeof(line));

        if (ret == 1 && line[0]) {
            cJSON *object = cJSON_CreateObject();
            cJSON_AddItemToArray(data->object, object);
            cJSON_AddStringToObject(object, "framework_version", line);
            path[len] = '\0';
            cJSON_AddStringToObject(object, "framework_path", path);
            cJSON_AddStringToObject(object, "framework_name", web_frame_info[i].name);
            cJSON_AddStringToObject(object, "framework_language", web_frame_info[i].language);
            // dlog("===%d====%s===%s\n", ret, web_frame_info[i].name, line);
            web_framework[web_frame_info[i].type] = 1;
            break;
        }

        i ++;
    }

    web_framework[WEBFRAME_YII] = 1;

    return 0;
}
/* cakephp框架是单独的进程，不依赖apache/nginx的中间件 */
static int get_php_cake_info(const char *pid, sys_info_t *data)
{
    char web_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    unsigned char line[PATH_MAX] = {0};
    char version[64] = {0};
    char *tmp = NULL;
    int len = 0;
    int ret = 0;
    int i = 0;
    int found = 0;
    if (pid == NULL || data == NULL || data->object == NULL) return -1;

    if (web_framework[WEBFRAME_CAKEPHP] != 0) {
        return -1;
    }

    /* get cmdline */
    memset(path, 0x00, sizeof(path));
    tmp = get_cmd_line_by_pid(pid);
    if (!tmp) {
        return -1;
    }

    snprintf(path, sizeof(path), "%s", tmp);
    if (tmp) {
        free(tmp);
        tmp = NULL;
    }

    tmp = strstr(path, "-S");
    if (tmp) {
        tmp = strstr(path, "-t");
        if (!tmp) {
            return -1;
        }
        tmp = strstr(path, "webroot/index.php");
        if (!tmp) {
            return -1;
        }
    }

    tmp = strstr(path, "-t");
    if (!tmp) {
        return -1;
    }
    tmp += 2;
    tmp = strchr(tmp, '/');
    if (!tmp) {
        return -1;
    }

    memset(web_path, 0x00, sizeof(web_path));
    snprintf(web_path, sizeof(web_path), "%s", tmp);
    tmp = strstr(web_path, "/webroot");
    if (!tmp) {
        return -1;
    }
    *tmp = '\0';

    while (web_frame_info[i].cheak_file[0]) {
        if (web_frame_info[i].type != WEBFRAME_CAKEPHP) {
            ++ i;
            continue;
        }

        if (web_framework[web_frame_info[i].type] == 1) { // 已经查到了不重复查
            i ++;
            continue;
        }

        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/%s", web_path, web_frame_info[i].cheak_file);

        if (is_file(path) != 0) {
            i ++;
            continue;
        }

        if (web_frame_info[i].flag && found != web_frame_info[i].type) {
            found = web_frame_info[i].type;
        }

        if (web_frame_info[i].flag == WEBFRAME_CAKEPHP) { /* 因为新版本原因框架名和版本需要特殊处理的 */
            int flag = 0;
            FILE *fp = fopen(path, "r");
            if (!fp) {
                i ++;
                continue;
            }
            memset (line, 0x00, sizeof(line));
            while (fgets(line, sizeof(line), fp) != NULL) {
                if (!flag) {
                    if (strstr(line, "\"cakephp/cakephp\"")) { /* 找到这一行，下一条version才是正确的版本号 */
                        flag = 1;
                    }
                } else {
                    tmp = strstr(line, "version");
                    if (!tmp) {
                        continue;
                    }
                    tmp += 8;
                    tmp = strchr(tmp, '\"');
                    if (tmp) {
                        ++ tmp;
                        snprintf(line, sizeof(line), "%s", tmp);
                        tmp = strchr(line, '\"');
                        if (tmp) {
                            *tmp = '\0';
                        }
                        break;
                    }
                }
            }
            fclose(fp);
            if (line[0]) {
                ret = 1;
                goto INSERT;
            }
        }

        if (web_frame_info[i].flag) { // flag是1表示该文件只要存在即可，0表需要下面正则去匹配
            i ++;
            continue;
        }

        if (found != web_frame_info[i].type) {
            i ++;
            continue;
        }
        // dlog("-(%d)--%d--%d---%s--%s\n", i, found, web_frame_info[i].type, path, web_frame_info[i].regex);
        memset (line, 0x00, sizeof(line));
        ret = match_file_with_regex(path, web_frame_info[i].regex, line, sizeof(line));
INSERT:
        if (ret == 1 && line[0]) {
            cJSON *object = cJSON_CreateObject();
            cJSON_AddItemToArray(data->object, object);
            cJSON_AddStringToObject(object, "framework_version", line);
            cJSON_AddStringToObject(object, "framework_path", web_path);
            cJSON_AddStringToObject(object, "framework_name", web_frame_info[i].name);
            cJSON_AddStringToObject(object, "framework_language", web_frame_info[i].language);
            // dlog("===%d====%s===%s\n", ret, web_frame_info[i].name, line);
            web_framework[web_frame_info[i].type] = 1;
            break;
        }

        i ++;
    }

    return 0;
}

/**************************************************************************************************
 * 函数名: get_python_web2py_info
 * 作用: 检测Python web框架web2py，获取版本，路径信息
 * 输入: pid   进程pid
 *      data  连接每个模块Json信息，以及db描述符
 * 输出: web2py框架 Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 1)一般比较理想的情况下
 *      通过/proc/pid/cmdline获取we2py.py所在路径
 *      版本，读取文件VERSION文件中Version关键字
 *      安装路径，/proc/pid/cmdline获取的绝对路径
 * 
 *      2)另一种情况，通过/proc/pid/exe 获取python环境的安装目录
 *      再通过site-packages目录下的框架名来确认是否符合当前检测的框架名
**************************************************************************************************/
static int get_python_web2py_info(const char *pid, sys_info_t *data)
{
    char abs_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    unsigned char line[PATH_MAX] = {0};
    char version[64] = {0};
    int len = 0;
    int ret = 0;
    int fd = 0;
    unsigned char *tmp = NULL;
    unsigned char *end = NULL;

    if (pid == NULL || data == NULL || data->object == NULL) return -1;

    if (web_framework[WEBFRAME_Web2py] != 0) {
        return -1;
    }

    /* get cmdline */
    memset(path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    memset(line, 0x00, sizeof(line));
    fd = open(path, O_RDONLY);
    len = read(fd, line, sizeof(line));
    end = line + len;
    for (tmp=line; tmp<end; tmp++) {
        if (*tmp == 0) {
            *tmp = ' ';
        }
    }
    close(fd);

    tmp = strstr(line, "web2py.py");
    if (tmp) {
        /* 对于命令行中带有web2py.py的情况，直接源码引用的情况
         * 通过查找/proc/pid/environ中的PWD=后面的路径来确定web2的目录
         */
        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "/proc/%s/environ", pid);
        memset(line, 0x00, sizeof(line));
        fd = open(path, O_RDONLY);
        len = read(fd, line, sizeof(line));
        end = line + len;
        for (tmp=line; tmp<end; tmp++) {
            if (*tmp == 0) {
                *tmp = ' ';
            }
        }
        close(fd);
        tmp = strstr(line, "PWD=");
        if (tmp) {
            tmp += 4;
            /* 框架所在的目录 */
            memset(abs_path, 0x00, sizeof(abs_path));
            snprintf(abs_path, sizeof(abs_path), "%s", tmp);
            tmp = strchr(abs_path, ' ');
            if (tmp) {
                *tmp = '\0';
            }

            if (is_dir(abs_path) != 0) {
                return -1;
            }
        } else {
            return -1;
        }

        memset(path, 0x00, sizeof(path));
        snprintf(path, sizeof(path), "%s/VERSION", abs_path);
        memset(line, 0x00, sizeof(line));
        memset(version, 0x00, sizeof(version));
        if (is_file(path) == 0
            && find_key_from_file(path, "Version", line, sizeof(line), 0) == 0) {
            tmp = strstr(line, "Version");
            if (tmp) {
                tmp += strlen("Version");
                while(*tmp == ' ') {
                    tmp ++;
                }
                snprintf(version, sizeof(version), "%s", tmp);
                tmp = strchr(version, '+');
                if (tmp) {
                    *tmp = '\0';
                }
                len = strlen(version);
                if (version[len-1] == '\n') {
                    version[len-1] = '\0';
                }
            }
        } else {
            return -1;
        }
    } else { /* 直接引用安装库的情况 */
        /* 对于直接运行的情况，python3 ./abc.py 只需在abc.py 使用import web引用该框架包即可
         * 去当前python版本的安装目录找site-packages目录，再查对应的框架包名
         * 默认安装目录，Centos/Ubuntu是一致的/usr/local/lib/python(2.7/3.x)/site-packages/
         * TODO 非默认安装需要再区分是不是虚拟环境中的python环境，这种可以没有任何依赖直接运行一个应用(框架)
         * site-packages目录中一般一个包会有两个目录对应，比如web2py和web2py-0.62-py3.6.egg-info
         * 其中一个会带有相应的版本信息，此版本信息会随着pipe/pip3命令解析的依赖包的不而不同
         * 即，同一个python3的环境，用pip/pip3安装的版本可能会不同，属于正常的
         */
        memset(path, 0x00, sizeof(path));
        memset(abs_path, 0x00, sizeof(abs_path));
        snprintf(path, sizeof(path), "/proc/%s/exe", pid);
        len = readlink(path, abs_path, PATH_MAX);
        if (len < 0) {
            return -1;
        }
        /* 只看/usr/bin/python部分，不关心具体哪个版本
         * 能匹配上按默认安装的python的环境找site-packages
         */
        if (strncmp(abs_path, "/usr/bin/python", 15) != 0) {
            return -1;
        }

        int flags = 0;
try_again:
        memset(version, 0x00, sizeof(version));
        memset(path, 0x00, sizeof(path));
        if (!flags) { /* 32位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", "/usr/local/lib/", basename(abs_path));
        } else { /* 64位 */
            snprintf(path, sizeof(path), "%s/%s/site-packages/", "/usr/local/lib64/", basename(abs_path));
        }
        memset (line, 0x00, sizeof(line));
        if (find_file_in_dir(path, "web2py-", NULL, line, sizeof(line)) == 1) {
            tmp = strstr(line, "web2py-");
            if (!tmp) {
                return -1;
            }
            tmp += 7;
            snprintf(version, sizeof(version), "%s", tmp);
            tmp = strchr(version, '-');
            if (tmp) {
                *tmp = '\0';
            }
        }
        if (!version[0] && flags == 0) {
            flags = 1;
            goto try_again;
        }
    }
    if (!version[0]) {
        return -1;
    } 

    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    cJSON_AddStringToObject(object, "framework_version", version);
    cJSON_AddStringToObject(object, "framework_path", abs_path);
    cJSON_AddStringToObject(object, "framework_name", "Web2py");
    cJSON_AddStringToObject(object, "framework_language", "Python");

    web_framework[WEBFRAME_Web2py] = 1;

    return ret;
}

/**************************************************************************************************
 * 函数名: get_virtual_env_django_info
 * 作用: 检测Python web框架django，获取版本，路径信息
 * 输入: pid   进程pid
 *      data  连接每个模块Json信息，以及db描述符
 * 输出: django框架 Json数据
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 通过/proc/pid/cmdline参数runserver确定是Django
 *      版本，暂未获取到
 *      安装路径，/proc/pid/fd目录下的文件获取绝对路径
**************************************************************************************************/
static int get_virtual_env_django_info(const char *pid, sys_info_t *data)
{
    char abs_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char *tmp = NULL;
    int i = 0;
    int ret = 0;

    if (pid == NULL || data == NULL || data->object == NULL) return -1;

    if (web_framework[WEBFRAME_DJANGO] != 0) {
        return 0;
    }

    memset(path, 0x00, sizeof(path));
    memset(line, 0x00, sizeof(line));
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    FILE *f = fopen(path, "rb");
    i = fread(line, 1, sizeof(line), f);
    fclose(f);

    while (i) {
        if (!line[i]) line[i] = ' ';
        -- i;
    }

    tmp = strstr(line, "runserver");
    if (tmp) {
        tmp += strlen("runserver") + 1;
    }
    else {
        return -1;
    }
    /* framework path */
    DIR *dirp = NULL;
    struct dirent *dent = NULL;
    int len = 0;
    memset(path, 0x00, sizeof(path));
    memset(abs_path, 0x00, sizeof(abs_path));
    snprintf(path, sizeof(path), "/proc/%s/fd", pid);
    dirp = opendir(path);
    if (dirp == NULL) {
        return -1;;
    }
    while ((dent = readdir(dirp)) != NULL) {
        if (dent->d_name[0] < '0' || dent->d_name[0] > '9') continue;

        memset(path, 0x00, sizeof(path));
        memset(abs_path, 0x00, sizeof(abs_path));
        snprintf(path, sizeof(path), "/proc/%s/fd/%s", pid, dent->d_name);
        len = readlink(path, abs_path, PATH_MAX);
        if (len < 0) continue;
        if (strncmp(abs_path, "/dev/", 5) == 0) {
            continue;
        }

        break;
    }
    closedir(dirp);
    if (strncmp(abs_path, "/dev/", 5) == 0) {
        return -1;;
    }
    cJSON *object = cJSON_CreateObject();
    cJSON_AddItemToArray(data->object, object);
    /* Django version */
    /* 虚拟环境下获取版本信息 
     * cd ~/newproject/
     * source newenv/bin/activate
     * deactivate（退出虚拟环境
     * 从外暂时无法获取，设置为None
     */
    cJSON_AddStringToObject(object, "framework_version", "None");
    cJSON_AddStringToObject(object, "framework_path", dirname(abs_path));
    cJSON_AddStringToObject(object, "framework_name", "Django");
    cJSON_AddStringToObject(object, "framework_language", "Python");

    web_framework[WEBFRAME_DJANGO] = 1;

    return ret;
}

/* python/PHP的框架匹配
 * 当前的这种方式不依赖任何中间件的支持，可以直接运行监听端口提供服务
 */
static int get_no_middler_web_framework_info(sys_info_t *data)
{
    char framework_path[PATH_MAX] = {0};
    char framework_name[NAME_MAX] = {0};
    char framework_version[NAME_MAX] = {0};
    char framework_language[64] = {0};
    sqlite3_stmt * stmt = NULL;
    const char *zTail;
    const char *query_process = "select pid,name,user from sys_process;";
    int ret = 0;
    int i = 0;

    if (data->object == NULL || data->db == NULL) return -1;

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, query_process, -1, &stmt, &zTail);
    if (ret !=SQLITE_OK){
        elog("No process info\n");
    }
    else {
        data->ret = (void*)stmt;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *pid = sqlite3_column_text(stmt, 0);
        const char *process_path = sqlite3_column_text(stmt, 1);
        const char *process_user = sqlite3_column_text(stmt, 2);

        if (process_path[0] != '/') continue;

        /* Python语言Django框架在虚拟环境下部署不需要中间件 */
        char *tmp = strstr(process_path, "python");
        if (tmp) {
            /* TODO 
             * 1)注意区分下自定义安装和默认安装，以及虚拟环境的不同
             * 2)考虑抽出一个公共函数，指定查找的框架名和版本信息，减少代码冗余
             */
            get_virtual_env_django_info(pid, data);
            get_python_flask_info(pid, data);
            get_python_tornado_info(pid, data);
            get_python_webpy_info(pid, data);
            get_python_web2py_info(pid, data);
        }
        /* PHP的cake/YII框架不需要中间件 */
        tmp = strstr(process_path, "php");
        if (tmp) {
            get_php_cake_info(pid, data);
            get_php_yii_info(pid, data);
        }
    }
    sqlite3_finalize(stmt);

    return ret;
}

/**************************************************************************************************
 * 函数名: get_tomcat_access_path
 * 作用: 根据tomcat中间件配置文件获取配置的访问目录
 * 输入: tomcat    中间件结构体
 * 输出: tomcat的访问路径
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 未指定<const path的视为默认目录
 *      自定义目录的，查找<context docBase=/www/a/xuexi path="/xuexi" />关键字<context
**************************************************************************************************/
static int get_tomcat_access_path(midd_t *tomcat)
{
    char line[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    int ret = 0;
    int i = 0;
    int offset = 0;

    if (tomcat == NULL) {
        return -1;
    }

    if (tomcat->midd_type != MID_TOMCAT) {
        return -1;
    }

    if (tomcat->access_path[0]) { // 已经有了
        return 0;
    }

    if (is_file(tomcat->conf_path) != 0) {
        return -1;
    }

    fp = fopen(tomcat->conf_path, "r");
    if (!fp) {
        elog("tomcat conf open failed, %s\n", tomcat->conf_path);
        return -1;
    }

    // <Context path="" docBase="myjsp" debug="0" reloadable="true" />
    // 查找<Context开头的path=关键字
    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        if (line[0] == '<' && line[1] == '!') { // xml注释
            continue;
        }
        // 保留一份原字符串
        snprintf(path, sizeof(path), "%s", line);

        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }
        tmp = strstr(line, "<context");
        if (!tmp) {
            continue;
        }

        tmp += 8;
        tmp = strstr(tmp, "path=\"");
        if (!tmp) {
            continue;
        }
        tmp += 6;
        
        while (*tmp == ' ') {
            tmp ++;
        }
        // 求出tmp在line数组中的偏移，同样的在path数组中偏移即可得到原字符串的目录
        offset = abs(tmp-line);
        if (offset >= sizeof(line)) { // 超长了
            continue;
        }

        snprintf(tomcat->access_path, sizeof(tomcat->access_path), "%s", path + offset);
        tmp = strchr(tomcat->access_path, '\"');
        if (tmp) {
            *tmp = '\0';
        }

        if (is_dir(tomcat->access_path) == 0) {
            break;
        }
        memset(tomcat->access_path, 0x00, sizeof(tomcat->access_path));
    }

    fclose(fp);

    if (!tomcat->access_path[0]) { // 默认ROOT目录
        snprintf(tomcat->access_path, sizeof(tomcat->access_path), "%s/webapps/ROOT/", tomcat->install_path);
    }

    return ret;
}

/**************************************************************************************************
 * 函数名: get_nginx_access_path
 * 作用: 根据nginx中间件配置文件获取配置的访问目录
 * 输入: nginx    中间件结构体
 * 输出: nginx的访问路径
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 无
**************************************************************************************************/
static int get_nginx_access_path(midd_t *nginx)
{
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    int ret = 0;
    int i = 0;
    int offset = 0;

    if (nginx == NULL) {
        return -1;
    }

    if (nginx->midd_type != MID_NGINX) {
        return -1;
    }

    if (nginx->access_path[0]) { // 已经有了
        return 0;
    }

    if (is_file(nginx->conf_path) != 0) {
        return -1;
    }

    fp = fopen(nginx->conf_path, "r");
    if (!fp) {
        elog("nginx conf open failed, %s\n", nginx->conf_path);
        return -1;
    }

    // 查找root /www/server/phpmyadmin;
    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '<' || line[0] == '\n') {
            continue;
        }
        // 保留一份原字符串
        snprintf(path, sizeof(path), "%s", line);
        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }

        tmp = strstr(line, "root");
        if (tmp) {
            tmp += 4;
            while (*tmp == ' ') {
                tmp ++;
            }

            offset = abs(tmp-line);
            if (offset >= sizeof(line)) { // 超长了
                continue;
            }
            snprintf(nginx->access_path, sizeof(nginx->access_path), "%s", path + offset);
            tmp = strchr(nginx->access_path, ';');
            if (tmp) {
                *tmp = '\0';
            }
            if (is_dir(nginx->access_path) == 0) {
                break;
            }
            memset(nginx->access_path, 0x00, sizeof(nginx->access_path));
        }
    }

    fclose(fp);

    return ret;
}

static char *get_path_from_conf(const char *conf_path, char *key)
{
    char access_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char lower_key[128] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    int i = 0;
    int offset = 0;
    int len = 0;

    if (conf_path == NULL || key == NULL) {
        return strdup("");
    }

    len = strlen(key);
    for (i=0; i<=len; i++) {
        lower_key[i] = tolower(key[i]);
    }

    fp = fopen(conf_path, "r");
    if (!fp) {
        elog("apache conf open failed, %s\n", conf_path);
        return strdup("");
    }

    // 查找配置文件中查找DocumentRoot "/data/www/root"或<Directory "/data/www/root">
    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    memset (access_path, 0x00, sizeof(access_path));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '<' || line[0] == '\n') {
            continue;
        }
        // 保留一份原字符串
        snprintf(path, sizeof(path), "%s", line);
        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }

        tmp = strstr(line, lower_key);
        if (tmp) {
            tmp += strlen(lower_key); // DocumentRoot
            if (!tmp) {
                continue;
            }

            tmp = strchr(line, '/');
            if (!tmp) {
                continue;
            }

            offset = abs(tmp-line);
            if (offset >= sizeof(line)) { // 超长了
                continue;
            }

            snprintf(access_path, sizeof(access_path), "%s", path + offset);

            len = strlen(access_path);
            if (access_path[len-1] == '\n') {
                access_path[len-1] = '\0';
            }
            if (is_dir(access_path) == 0) {
                break;
            }
            memset(access_path, 0x00, sizeof(access_path));
        }
    }

    fclose(fp);

    if (access_path[0]) {
        return strdup(access_path);
    } else {
        return strdup("");
    }

    return strdup("");
}

/* apache还可以在 sites-available目录下配置多个站点 */
static int get_apache_sites_available_access_path(sys_info_t *data, midd_t *apache)
{
    char path[PATH_MAX] = {0};
    char old_acces_path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    DIR *dirp = NULL;
    struct dirent *iter_ent = NULL;
    int ret = 0;
    int i = 0;
    int offset = 0;

    if (data == NULL || apache == NULL) {
        return -1;
    }

    if (apache->midd_type != MID_APACHE) {
        return -1;
    }

    memset (old_acces_path, 0x00, sizeof(old_acces_path));
    snprintf(old_acces_path, sizeof(old_acces_path), "%s", apache->access_path);

    memset (path, 0x00, sizeof(path));
#ifdef SNIPER_FOR_DEBIAN
    snprintf(path, sizeof(path), "%s/sites-available", dirname(apache->conf_path));
#else
    snprintf(path, sizeof(path), "%s/conf.d", dirname(apache->conf_path));
#endif
    if (is_dir(path) != 0) { /* 没有此目录返回 */
        return -1;
    }

    offset = strlen(path);

    dirp = opendir(path);
    if (!dirp) {
        return -1;
    };

    while ((iter_ent = readdir(dirp))) {
        if (strncmp(iter_ent->d_name, ".", 1) == 0 || strncmp(iter_ent->d_name, "..", 2) == 0) {
            continue;
        }

        snprintf(path+offset, sizeof(path)-offset, "/%s", iter_ent->d_name);
        tmp = get_path_from_conf(path, "documentroot");
        if (!tmp) {
            continue;
        }
        if (is_dir(tmp) == 0) {
            if (strcmp(tmp, old_acces_path) == 0) { /* 中间件配置的访问目录相同不重复检查  */
                free(tmp);
                tmp = NULL;
                continue;
            }
            /* 更新中间件的访问目录从上层目录开始找 */
            memset(apache->access_path, 0x00, sizeof(apache->access_path));
            snprintf(apache->access_path, sizeof(apache->access_path), "%s", dirname(tmp));
            get_web_framework_info(data, apache);
            // 加深一层目录
            get_dir_web_framework(data, apache);
        }
        free(tmp);
        tmp = NULL;
    }
    closedir(dirp);

    snprintf(apache->conf_path, sizeof(apache->conf_path), "%s", old_acces_path);

    return 0;
}

static int get_apache_multiple_access_path(sys_info_t *data, midd_t *apache)
{
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    int ret = 0;
    int i = 0;
    int offset = 0;

    if (apache == NULL) {
        return -1;
    }

    if (apache->midd_type != MID_APACHE) {
        return -1;
    }

    if (is_file(apache->conf_path) != 0) {
        return -1;
    }

    fp = fopen(apache->conf_path, "r");
    if (!fp) {
        elog("apache conf open failed, %s\n", apache->conf_path);
        return -1;
    }

    // 查找配置文件中查找<Directory "/data/www/root">
    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        // 保留一份原字符串
        snprintf(path, sizeof(path), "%s", line);
        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }

        tmp = strstr(line, "<directory");
        if (tmp) {
            tmp = strchr(tmp, '/');
            if (!tmp) {
                continue;
            }
            snprintf(apache->access_path, sizeof(apache->access_path), "%s", tmp);
            tmp = strchr(apache->access_path, '>');
            if (tmp) {
                *tmp = '\0';
            }
            if (strlen(apache->access_path) == 1) { /* 是根目录 */
                continue;
            }

            if (is_dir(apache->access_path) == 0) {
                get_web_framework_info(data, apache);
                if (is_found_web_framework() == 0) { // 未检测到,加深一层目录
                    get_dir_web_framework(data, apache);
                }
            }
            memset(apache->access_path, 0x00, sizeof(apache->access_path));
        }
    }

    fclose(fp);

    return ret;
}

static char *get_nginx_root_conf(const char *conf_path)
{
    char access_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char *lower_key = "root";
    FILE *fp = NULL;
    char *tmp = NULL;
    int i = 0;
    int offset = 0;
    int len = 0;

    if (conf_path == NULL) {
        return strdup("");
    }

    fp = fopen(conf_path, "r");
    if (!fp) {
        elog("apache conf open failed, %s\n", conf_path);
        return strdup("");
    }

    // 查找配置文件中查找include
    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    memset (access_path, 0x00, sizeof(access_path));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        tmp = strchr(line, '#');
        if (tmp) { /* 有#视为注释行 */
            continue;
        }
        // 保留一份原字符串
        snprintf(path, sizeof(path), "%s", line);
        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }

        tmp = strstr(line, lower_key);
        if (tmp) {
            tmp += strlen(lower_key); // DocumentRoot
            if (!tmp) {
                continue;
            }

            tmp = strchr(line, '/');
            if (!tmp) {
                continue;
            }
            //20220629 当前流程未考虑相对路径清空，导致错误地去遍历/目录下的文件
            //如果/目录下有大文件，那资产清点的时间就会超长
            //TODO 处理相对路径
            if (*(tmp-1) != ' ') {
                continue;
            }

            offset = abs(tmp-line);
            if (offset >= sizeof(line)) { // 超长了
                continue;
            }

            snprintf(access_path, sizeof(access_path), "%s", path + offset);

            len = strlen(access_path);
            if (access_path[len-1] == '\n') {
                access_path[len-1] = '\0';
            }
            tmp = strchr(access_path, ';');
            if (tmp) { /* 有点说明有具体的配置，比如/path/*.conf或者/path/a.conf */
                *tmp = '\0';
            }
            delete_tailspace(access_path);

            if (is_dir(access_path) == 0) {
                break;
            }
            memset(access_path, 0x00, sizeof(access_path));
        }
    }

    fclose(fp);

    if (access_path[0]) {
        return strdup(access_path);
    } else {
        return strdup("");
    }

    return strdup("");
}
static char *get_nginx_include_conf(const char *conf_path)
{
    char access_path[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    char *lower_key = "include";
    FILE *fp = NULL;
    char *tmp = NULL;
    int i = 0;
    int offset = 0;
    int len = 0;

    if (conf_path == NULL) {
        return strdup("");
    }

    fp = fopen(conf_path, "r");
    if (!fp) {
        elog("apache conf open failed, %s\n", conf_path);
        return strdup("");
    }

    // 查找配置文件中查找include
    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    memset (access_path, 0x00, sizeof(access_path));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        tmp = strchr(line, '#');
        if (tmp) { /* 有#视为注释行 */
            continue;
        }
        // 保留一份原字符串
        snprintf(path, sizeof(path), "%s", line);
        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }

        tmp = strstr(line, lower_key);
        if (tmp) {
            tmp += strlen(lower_key); // DocumentRoot
            if (!tmp) {
                continue;
            }

            tmp = strchr(line, '/');
            if (!tmp) {
                continue;
            }
            //20220629 当前流程未考虑相对路径清空，导致错误地去遍历/目录下的文件
            //如果/目录下有大文件，那资产清点的时间就会超长
            //TODO 处理相对路径
            if (*(tmp-1) != ' ') {
                continue;
            }

            offset = abs(tmp-line);
            if (offset >= sizeof(line)) { // 超长了
                continue;
            }

            snprintf(access_path, sizeof(access_path), "%s", path + offset);

            len = strlen(access_path);
            if (access_path[len-1] == '\n') {
                access_path[len-1] = '\0';
            }
            tmp = strchr(access_path, '.');
            if (tmp) { /* 有点说明有具体的配置，比如/path/*.conf或者/path/a.conf */
                dirname(access_path);
            }

            if (is_dir(access_path) == 0) {
                break;
            }
            memset(access_path, 0x00, sizeof(access_path));
        }
    }

    fclose(fp);

    if (access_path[0]) {
        return strdup(access_path);
    } else {
        return strdup("");
    }

    return strdup("");
}
static int get_nginx_multiple_access_path(sys_info_t *data, midd_t *nginx)
{
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    FILE *fp = NULL;
    DIR *dirp = NULL;
    struct dirent *iter_ent = NULL;
    char *tmp = NULL;
    char *end = NULL;
    char *tmp_path = NULL;
    int ret = 0;
    int i = 0;
    int offset = 0;

    if (data == NULL || nginx == NULL) {
        return -1;
    }
    if (nginx->midd_type != MID_NGINX) {
        return -1;
    }

    if (is_file(nginx->conf_path) != 0) {
        return -1;
    }
    /* 查找nginx配置中的include配置项 */
    tmp = get_nginx_include_conf(nginx->conf_path);
    if (!tmp) {
        /* 没找到include的多个配置文件 */
        return -1;
    }
    /* 获取多个配置所在的目录，一般类似 /path/*.conf */
    memset (path, 0x00, sizeof(path));
    snprintf(path, sizeof(path), "%s", tmp);
    free(tmp);
    tmp = NULL;

    tmp_path = strchr(path, '/');
    if (!tmp_path) {
        return -1;
    }
    
    tmp = strchr(tmp_path, ';');
    if (tmp) {
        *tmp;
    }
    delete_tailspace(path);
    if (is_dir(path) != 0) {
        return -1;
    }
    
    offset = strlen(path);
    dirp = opendir(path);
    if (!dirp) {
        return -1;
    };

    while ((iter_ent = readdir(dirp))) {
        if (strncmp(iter_ent->d_name, ".", 1) == 0 || strncmp(iter_ent->d_name, "..", 2) == 0) {
            continue;
        }
        snprintf(path+offset, sizeof(path)-offset, "/%s", iter_ent->d_name);

        tmp = get_nginx_root_conf(path);
        if (!tmp) {
            continue;
        }
        end = strchr(tmp, ';');
        if (end) {
            *end = '\0';
        }

        if (is_dir(tmp) != 0) { /* 检查root 配置是不是目录 */
            free(tmp);
            tmp = NULL;
            continue;
        }

        /* 有效目录，进行框架匹配 */
        memset(nginx->access_path, 0x00, sizeof(nginx->access_path));
        snprintf(nginx->access_path, sizeof(nginx->access_path), "%s", tmp);
        get_web_framework_info(data, nginx);
        if (is_found_web_framework() == 0) { // 未检测到,加深一层目录
            get_dir_web_framework(data, nginx);
        }

        free(tmp);
        tmp = NULL;
    }
    closedir(dirp);

    return 0;
}
/**************************************************************************************************
 * 函数名: get_apache_access_path
 * 作用: 根据apache中间件配置文件获取配置的访问目录
 * 输入: apache    中间件结构体
 * 输出: apache的访问路径
 * 返回值: 成功返回，0
 *        失败返回，-1
 * 其它: 无
**************************************************************************************************/
static int get_apache_access_path(midd_t *apache)
{
    char path[PATH_MAX] = {0};
    char line[PATH_MAX] = {0};
    FILE *fp = NULL;
    char *tmp = NULL;
    int ret = 0;
    int i = 0;
    int offset = 0;

    if (apache == NULL) {
        return -1;
    }

    if (apache->midd_type != MID_APACHE) {
        return -1;
    }

    if (apache->access_path[0]) { // 已经有了
        return 0;
    }

    if (is_file(apache->conf_path) != 0) {
        return -1;
    }

    fp = fopen(apache->conf_path, "r");
    if (!fp) {
        elog("apache conf open failed, %s\n", apache->conf_path);
        return -1;
    }

    // 查找配置文件中查找DocumentRoot "/data/www/root"或<Directory "/data/www/root">
    memset (path, 0x00, sizeof(path));
    memset (line, 0x00, sizeof(line));
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '<' || line[0] == '\n') {
            continue;
        }
        // 保留一份原字符串
        snprintf(path, sizeof(path), "%s", line);
        for (i=0; i<sizeof(line); i++) {
            line[i] = tolower(line[i]);
        }

        tmp = strstr(line, "documentroot");
        if (tmp) {
            tmp += 12; // DocumentRoot
            if (!tmp) {
                continue;
            }
            tmp = strchr(tmp, '\"');
            if (!tmp) {
                continue;
            }
            tmp ++;

            offset = abs(tmp-line);
            if (offset >= sizeof(line)) { // 超长了
                continue;
            }
            snprintf(apache->access_path, sizeof(apache->access_path), "%s", path + offset);

            tmp = strchr(apache->access_path, '\"');
            if (tmp) {
                *tmp = '\0';
            }
            if (is_dir(apache->access_path) == 0) {
                break;
            }
            memset(apache->access_path, 0x00, sizeof(apache->access_path));
        }
    }

    fclose(fp);

    return ret;
}

/* JSON web_framework */
void *sys_web_framework_info(sys_info_t *data)
{
    sqlite3_stmt *stmt = NULL;
    const char *zTail = NULL;
    int i = 0;
    int ret = 0;

    if (data->object == NULL) return NULL;

    /* query process from db */
    ret = sqlite3_prepare_v2(data->db, query_web_middler, -1, &stmt, &zTail);
    if (ret !=SQLITE_OK){
        elog("No process info\n");
    }
    else {
        data->ret = (void*)stmt;
    }
    ret = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *pid = sqlite3_column_text(stmt, 0);
        const char *process_path = sqlite3_column_text(stmt, 1);
        const char *process_user = sqlite3_column_text(stmt, 2);

        if (process_path[0] != '/') continue;

        /* 任意中间件存在，即检测框架是否存在 */
        for (i = 0; i < MID_MAX; i++) {
            switch (midd_set[i].midd_type) {
            case MID_APACHE:
                // 获取中间件的访问路径,配置文件中查找DocumentRoot "/data/www/root"
                get_apache_access_path(&midd_set[i]);
                if (midd_set[i].access_path[0]) { /* 找到访问目录即已配置DocumentRoot */
                    get_web_framework_info(data, &midd_set[i]);
                    if (is_found_web_framework() == 0) { // 未检测到,加深一层目录
                        get_dir_web_framework(data, &midd_set[i]);
                    }
                }
                /* 查找 <Directory配置的目录 */
                get_apache_multiple_access_path(data, &midd_set[i]);
                /* 查找 sites-available目录下配置的站点信息 */
                get_apache_sites_available_access_path(data, &midd_set[i]);
                break;
            case MID_NGINX:
                // 获取中间件的访问路径,配置文件中查找root /www/server/phpmyadmin;
                get_nginx_access_path(&midd_set[i]);
                get_web_framework_info(data, &midd_set[i]);
                if (is_found_web_framework() == 0) { // 未检测到,加深一层目录
                    get_dir_web_framework(data, &midd_set[i]);
                }
                get_nginx_multiple_access_path(data, &midd_set[i]);
                /* nginx可与tomcat中间件组合，查找java类的框架只在tomcat中间件中做即可，不重复查找 */
                break;
            case MID_TOMCAT:
                get_tomcat_access_path(&midd_set[i]);
                // struts框架只在Tomcat下有
                get_java_struts_struts2_info(data, &midd_set[i], 1);
                get_java_struts_struts2_info(data, &midd_set[i], 2);
                get_java_spring_info(data, &midd_set[i]);
                if (web_framework[WEBFRAME_SPRING] == 1) {
                    get_java_springmvc_info(data, &midd_set[i]);
                }
                /* TODO 在tomcat的配置文件web.xml中配置php-cgi，tomcat也支持PHP的解析，如果有此配置也需要匹配PHP的框架 */
                break;
            case MID_JBOSS:
            case MID_WEBLOGIC:
            case MID_JETTY:
            case MID_WEBSPHERE:
                /* 在安装目录下，一个应用一个目录，是单独的
                 * https://www.cnblogs.com/shawWey/p/9981505.html 启动介绍
                 */
            case MID_WILDFLY:
                break;
            default:
                break;
            }
        }
    }
    sqlite3_finalize(stmt);

    get_no_middler_web_framework_info(data);

    return NULL;
}
void *sys_web_framework_info_destroy(sys_info_t *data)
{
    if (data->object == NULL) return NULL;

    return NULL;
}
