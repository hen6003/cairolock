#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <cairo/cairo.h>
#include <cairo/cairo-xlib.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <pwd.h>

char passwd_buf[20] = "";
int override_redirect = 1;

int cairo_check_event(cairo_surface_t *sfc, int block)
{
  char keybuf[8];
  KeySym key;
  XEvent e;

  for (;;)
  {
    if (block || XPending(cairo_xlib_surface_get_display(sfc)))
      XNextEvent(cairo_xlib_surface_get_display(sfc), &e);
    else 
      return 0;

    switch (e.type)
    {
      case ButtonPress:
        return -e.xbutton.button;
      case KeyPress:
        XLookupString(&e.xkey, keybuf, sizeof(keybuf), &key, NULL);
        return key;
    }
  }
}

cairo_surface_t *cairo_create_x11_surface(int *x, int *y)
{
  Display *dsp;
  Drawable da;
  Screen *scr;
  Window root;
  int screen;
  cairo_surface_t *sfc;
  XSetWindowAttributes wa;
  wa.override_redirect = override_redirect;

  if ((dsp = XOpenDisplay(NULL)) == NULL)
    exit(1);
  screen = DefaultScreen(dsp);
  scr = DefaultScreenOfDisplay(dsp);
  root = DefaultRootWindow(dsp);

  *x = WidthOfScreen(scr), *y = HeightOfScreen(scr);
  da = XCreateWindow(dsp, root, 0, 0, *x, *y, 0, CopyFromParent, 
    InputOutput, CopyFromParent, CWOverrideRedirect, &wa);
 
  Cursor invisibleCursor;
  Pixmap bitmapNoData;
  XColor black;
  static char noData[] = { 0,0,0,0,0,0,0,0 };
  black.red = black.green = black.blue = 0;
  bitmapNoData = XCreateBitmapFromData(dsp, da, noData, 8, 8);
  invisibleCursor = XCreatePixmapCursor(dsp, bitmapNoData, bitmapNoData, 
                                           &black, &black, 0, 0);
  XDefineCursor(dsp, da, invisibleCursor);
  XFreeCursor(dsp, invisibleCursor);
  XFreePixmap(dsp, bitmapNoData);

  if (override_redirect)
    XGrabKeyboard(dsp, root, True, GrabModeAsync, GrabModeAsync, CurrentTime);

  XSelectInput(dsp, da, ButtonPressMask | KeyPressMask);
  XMapWindow(dsp, da);

  sfc = cairo_xlib_surface_create(dsp, da, DefaultVisual(dsp, screen), *x, *y);
  cairo_xlib_surface_set_size(sfc, *x, *y);

  return sfc;
}

void cairo_close_x11_surface(cairo_surface_t *sfc)
{
  Display *dsp = cairo_xlib_surface_get_display(sfc);

  cairo_surface_destroy(sfc);
  XCloseDisplay(dsp);
}

static void turn(double v, double max, double *diff)
{
  if (v <= 0 || v >= max)
    *diff *= -1.0;
}

int rand_num(int min, int max)
{
  int n = rand() % max + min;
  return n;
}

/* for pam conversation */
int conversation(int num_msg, const struct pam_message **msg,
     struct pam_response **resp, void *appdata_ptr)
{ /* We malloc an array of num_msg responses */
  struct pam_response *array_resp = (struct pam_response *)malloc(
    num_msg * sizeof(struct pam_response));
  for (int i = 0; i < num_msg; i++) {
    /* resp_retcode should be set to zero */
    array_resp[i].resp_retcode = 0;

    char passwd[20];

    /* This is a function that reads a line from console without printing it
     * just like when you digit your password on sudo. I'll publish this soon */
    // readPass(pass);
    strcpy(passwd, passwd_buf);

    /* Malloc-ing the resp string of the i-th response */
    array_resp[i].resp = (char *)malloc(strlen(passwd) + 1);

    /* Writing password in the allocated string */
    strcpy(array_resp[i].resp, passwd);
  }

  /* setting the param resp with our array of responses */
  *resp = array_resp;

  /* Here we return PAM_SUCCESS, which means that the conversation happened correctly.
   * You should always check that, for example, the user didn't insert a NULL password etc */
  return PAM_SUCCESS;
}

static struct pam_conv conv = {
  conversation, /* Our conversation function */
  NULL /* We don't need additional data now*/
};

int check_pam(char * user)
{
  pam_handle_t *handle = NULL;
  const char *service_name = "cairolock";
  int retval;

  retval = pam_start(service_name, NULL, &conv,
             &handle); /* Initializing PAM */
  if (retval != PAM_SUCCESS) {
    fprintf(stderr, "Failure in pam initialization: %s",
            pam_strerror(handle, retval));
    return 1;
  }

  pam_set_item(handle, PAM_USER, user);

  retval = pam_authenticate(
        handle,
          0); /* Do authentication (user will be asked for username and password)*/
  if (retval != PAM_SUCCESS) {
    return 1;
  }

  retval = pam_acct_mgmt(
        handle,
          0); /* Do account management (check the account can access the system) */
  if (retval != PAM_SUCCESS) {
    return 1;
  }

  pam_end(handle, retval); /* ALWAYS terminate the pam transaction!! */
  return 0;
}

int main(int argc, char **argv)
{
  cairo_surface_t *sfc;
  cairo_t * ctx;
  int x, y;
  struct timespec ts = {0, 5000000};
  int key_event;
  int input_len;
  char user[32] = "";
  char * custom_text = "Enter Password";
  int show_password = 0;
  register struct passwd *pw;
  register uid_t uid;

  srand(time(0));
  unsigned int running, login_failure = 0;

  for (optind = 1; optind < argc && argv[optind][0] == '-'; optind++)
  {
    for (int i = 1; i < strlen(argv[optind]); i++)
    {
    switch (argv[optind][i])
      {
        case 'd':
          override_redirect = 0;
          break;

        case 't':
          custom_text = &argv[optind+1][0];

          if (custom_text == NULL)
          {
            fprintf(stderr, "No argument given for -t\n"
                            "Try '%s -h' for more information\n", argv[0]);
            exit(2);
          }

          break;

        case 'p':
          show_password = 1;
          break;

        case 'h':
          printf("Usage: %s [OPTION]\n"
                 "Lock the screen until users password is inputted\n\n"
                 "  -d        do not lock the screen, will still use screen size for triangle\n"
                 "  -p        display the password\n"
                 "  -t [TEXT] display custom text\n"
                 "  -h        show this help\n", argv[0]);
          exit(0);
          break;
        
        default:
          if (argv[optind][0] != '-')
            break;

          fprintf(stderr, "Unknown argument: %c\n"
                          "Try '%s -h' for more information\n", argv[optind][i], argv[0]);
          exit(1);
          break;
      }
    }
  }
  
  uid = geteuid();
  pw = getpwuid(uid);
  strcpy(user, pw->pw_name);

  x = y = 0;
  sfc = cairo_create_x11_surface(&x, &y);
  ctx = cairo_create(sfc);
  
  double x0 = rand_num(1,x-1), y0 = rand_num(1,y-1), x1 = rand_num(1,x-1),
         y1 = rand_num(1,y-1), x2 = rand_num(1,x-1), y2 = rand_num(1,y-1); //TODO: adapt to screen size

  double dx0 = 1, dx1 = 1.5, dx2 = 2;
  double dy0 = 2, dy1 = 1.5, dy2 = 1;

  for (running = 1; running;)
  {
    cairo_push_group(ctx);
    cairo_select_font_face (ctx,
      "firamono",
      CAIRO_FONT_SLANT_NORMAL,
      CAIRO_FONT_WEIGHT_NORMAL);

    cairo_set_source_rgb(ctx, 0, 0, 0);
    cairo_paint(ctx);

    cairo_move_to(ctx, x0, y0);
    cairo_line_to(ctx, x1, y1);
    cairo_line_to(ctx, x2, y2);
    cairo_line_to(ctx, x0, y0);

    cairo_set_source_rgb(ctx, 0, 0, 1);
    cairo_fill_preserve(ctx);
    cairo_set_line_width(ctx, 5);

    cairo_set_source_rgb(ctx, 1, 1, 0);
    cairo_stroke(ctx);

    cairo_set_source_rgb(ctx, 1, 0, 0);
    cairo_move_to(ctx, x0, y0);
    cairo_show_text(ctx, "P0");
    cairo_move_to(ctx, x1, y1);
    cairo_show_text(ctx, "P1");
    cairo_move_to(ctx, x2, y2);
    cairo_show_text(ctx, "P2");

    cairo_set_source_rgb(ctx, 1, 1, 1);
    cairo_set_font_size(ctx, 20); 
    
    if (strcmp(custom_text, ""))
    {
      cairo_move_to(ctx, 20, 40);
      cairo_show_text(ctx, custom_text);
    }

    cairo_move_to(ctx, 100, 100);
    if (show_password)
      cairo_show_text(ctx, passwd_buf);
    else
    {
      char buf[20] = "";
      for (int i = 0; i < strlen(passwd_buf); i++)
        strcat(buf, "*");

      cairo_show_text(ctx, buf);
    }

    if (login_failure)
    {
      cairo_set_source_rgb(ctx, 1, 0, 0);
      cairo_move_to(ctx, 100, 120);
      cairo_show_text(ctx, "Failed to login");
      login_failure--;
    }
    
    cairo_pop_group_to_source(ctx);
    cairo_paint(ctx);
    cairo_surface_flush(sfc);

    x0 += dx0;
    y0 += dy0;
    x1 += dx1;
    y1 += dy1;
    x2 += dx2;
    y2 += dy2;
    turn(x0, x, &dx0);
    turn(x1, x, &dx1);
    turn(x2, x, &dx2);
    turn(y0, y, &dy0);
    turn(y1, y, &dy1);
    turn(y2, y, &dy2);

    key_event = cairo_check_event(sfc, 0);
    switch (key_event)
    {
      case 0xff08:
        input_len = strlen(passwd_buf);
        passwd_buf[input_len-1] = 0x0;
        break;

      case 0xff0d:
        if (check_pam(user))
          login_failure = 500; // the bigger the number the longer it shows
        else
          running = 0;
        strcpy(passwd_buf, "");
        break;

      default:
        if (isascii(key_event) && key_event != 0x0)
          if (strlen(passwd_buf) < 21)
            strcat(passwd_buf, (char*) &key_event);
    }

    nanosleep(&ts, NULL);
  }

  cairo_destroy(ctx);
  cairo_close_x11_surface(sfc);

  return 0;
}
